#!/usr/bin/env python3
"""
run_aes_toggle.py — AES toggle signal validation experiment.

Launches a SEV-SNP VM running guest_aes_toggle, which alternates between:
  Group A: AES with pt[0] in {0..7}   → accesses T0[0..7] → target cache line
  Group B: AES with pt[0] in {128..255} → accesses T0[128..255] → different page

The host preload (HR_MODE=aes_toggle) busy-polls the mailbox and probes the
target cache line immediately after each AES call. Outputs CSV + summary.

Usage:
  sudo -E python3 src/scripts/run_aes_toggle.py --iters 2000
  sudo -E python3 src/scripts/run_aes_toggle.py --iters 5000 --qemu-cpu 32
"""
from __future__ import annotations

import argparse
import csv
import os
import re
import statistics
import subprocess
import time
from pathlib import Path

import ch6_resctrl as rc
from ch5_common import collect_host_facts, timestamped_outdir_ch5, write_json
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

DONE_RE = re.compile(
    r"\[aes_toggle\] done iters=(\d+)\s+guest_total_aes_calls=(\d+)\s+guest_loop_cycles=(\d+)\s+guest_loop_ns=(\d+)\s+cycles_per_call=([0-9.]+)\s+ns_per_call=([0-9.]+)"
)


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


def launch_vm(args: argparse.Namespace, vm_dir: Path) -> subprocess.Popen:
    vm_dir.mkdir(parents=True, exist_ok=True)
    qemu_bin = resolve_path_with_fallback(
        QEMU_BIN, Path("<COHERE_REPO>/AMDSEV/qemu/build/qemu-system-x86_64")
    )
    ovmf_fd = resolve_path_with_fallback(
        OVMF_FD, Path("<COHERE_REPO>/AMDSEV/ovmf/Build/OvmfX64/DEBUG_GCC5/FV/OVMF.fd")
    )
    for p, name in [(qemu_bin, "QEMU"), (ovmf_fd, "OVMF"), (GUEST_KERNEL, "kernel"), (INITRAMFS, "initramfs")]:
        if not p.exists():
            raise SystemExit(f"[env] {name} not found: {p}")

    # guest_aes_toggle args passed via probe_mode and extra cmdline
    # Encode spaces as underscores for kernel cmdline (decoded by init)
    te0_arg = f"--te0-file-offset_0x{args.te0_file_offset:x}" if args.te0_file_offset else ""
    iters_arg = f"--iters_{args.iters}"
    aes_toggle_args = f"{te0_arg}_{iters_arg}".strip("_") if te0_arg else iters_arg

    append_parts = [
        "console=ttyS0",
        "rdinit=/init",
        "panic=-1",
        "quiet",
        "probe_mode=aes_toggle",
        f"probe_aes_toggle_args={aes_toggle_args}" if aes_toggle_args else "",
    ]
    extra = str(getattr(args, "guest_extra_cmdline", "")).strip()
    if extra:
        append_parts.append(extra)
    append = " ".join(p for p in append_parts if p)

    sync_log = vm_dir / "debugcon.log"
    preload_env = os.environ.copy()
    preload_env.update({
        "HR_MODE": "aes_toggle",
        "HR_OUTDIR": str(vm_dir),
        "HR_SYNC_LOG": str(sync_log),
        "HR_TID_FILE": str(vm_dir / "hr_thread.tid"),
        "HR_CPU": str(args.qemu_cpu),
        "HR_AES_TOGGLE_PROBE_MODE": str(args.probe_mode),
        "HR_AES_TOGGLE_BURST": str(int(args.probe_burst)),
        "HR_AES_TOGGLE_DELAY_US": str(int(args.probe_delay_us)),
        "HR_AES_TOGGLE_SCORE_MODE": str(args.probe_score_mode),
        "HR_AES_TOGGLE_SET_HOST_UC": "1" if bool(args.set_host_uc) else "0",
        "LD_PRELOAD": str(SRC_DIR / "build" / "libhost_runner.so"),
    })
    (vm_dir / ".hr_preload.lock").unlink(missing_ok=True)

    qemu_cmd = [
        str(qemu_bin),
        "-enable-kvm",
        "-cpu", args.cpu_model,
        "-machine", "q35,smm=off",
        "-machine", "confidential-guest-support=sev0,vmport=off",
        "-machine", "memory-backend=ram1",
        "-smp", str(args.smp),
        "-m", str(args.mem),
        "-no-reboot",
        "-object", f"memory-backend-memfd,id=ram1,size={args.mem},share=true,prealloc=false",
        "-object", "sev-snp-guest,id=sev0,policy=0x30000,cbitpos=51,reduced-phys-bits=1",
        "-bios", str(ovmf_fd),
        "-kernel", str(GUEST_KERNEL),
        "-initrd", str(INITRAMFS),
        "-append", append,
        "-serial", f"file:{vm_dir / 'qemu_console.log'}",
        "-chardev", f"file,id=debugcon,path={sync_log}",
        "-device", "isa-debugcon,iobase=0xe9,chardev=debugcon",
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
    return proc


def apply_resctrl_partition(args: argparse.Namespace, vm_dir: Path, qemu_pid: int) -> dict:
    prefix = str(args.resctrl_prefix or "cohch6")
    rc.cleanup_groups(prefix)
    rc.ensure_resctrl_mounted()
    cbm_mask = rc.read_l3_cbm_mask()
    host_mask, cvm_mask = rc.split_cbm_mask(cbm_mask)
    host_group = rc.create_group(f"{prefix}_host", l3_mask=host_mask, mba_percent=(int(args.resctrl_host_mba) if int(args.resctrl_host_mba) > 0 else None))
    cvm_group = rc.create_group(f"{prefix}_cvm", l3_mask=cvm_mask, mba_percent=100)

    hr_tid = rc.wait_for_tid_file(vm_dir / "hr_thread.tid", timeout_s=15.0)
    vcpu_tids, tasks = rc.wait_for_vcpu_tids(qemu_pid, timeout_s=15.0)
    all_tids = [tid for tid, _comm in tasks]
    host_tids = [tid for tid in all_tids if tid not in vcpu_tids]
    if hr_tid and hr_tid not in host_tids:
        host_tids.append(int(hr_tid))
    host_tids = rc.filter_live_tids(host_tids)
    vcpu_tids = rc.filter_live_tids(vcpu_tids)
    if not vcpu_tids:
        thread_dump = ", ".join(f"{tid}:{comm}" for tid, comm in tasks)
        raise SystemExit(f"[resctrl] failed to identify vCPU threads; threads={thread_dump}")

    rc.assign_tids(host_group, host_tids)
    rc.assign_tids(cvm_group, vcpu_tids)

    record = {
        "enabled": True,
        "cbm_mask_hex": f"0x{cbm_mask:x}",
        "host_mask_hex": f"0x{host_mask:x}",
        "cvm_mask_hex": f"0x{cvm_mask:x}",
        "host_group": str(host_group),
        "cvm_group": str(cvm_group),
        "qemu_pid": int(qemu_pid),
        "hr_tid": int(hr_tid) if hr_tid else None,
        "host_tids": host_tids,
        "vcpu_tids": vcpu_tids,
        "host_mba_percent": int(args.resctrl_host_mba) if int(args.resctrl_host_mba) > 0 else None,
    }
    write_json(vm_dir / "resctrl_assignment.json", record)
    return record


def cleanup_resctrl(args: argparse.Namespace) -> None:
    if not bool(args.resctrl_enable):
        return
    prefix = str(args.resctrl_prefix or "cohch6")
    rc.cleanup_groups(prefix)


def wait_done(vm_dir: Path, timeout_s: int) -> bool:
    done_path = vm_dir / "aes_toggle_done.txt"
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if done_path.exists():
            return True
        time.sleep(1.0)
    return False


def analyze(vm_dir: Path, outdir: Path) -> None:
    csv_path = vm_dir / "aes_toggle.csv"
    summary_path = vm_dir / "aes_toggle_summary.txt"
    serial_log = vm_dir / "qemu_console.log"

    if not csv_path.exists():
        print(f"[analyze] CSV not found: {csv_path}")
        return

    rows = []
    with csv_path.open() as f:
        for r in csv.DictReader(f):
            rows.append(r)

    a_tsc = [int(r["tsc_delta"]) for r in rows if r["group"] == "A"]
    b_tsc = [int(r["tsc_delta"]) for r in rows if r["group"] == "B"]

    def pct(vals: list[int], q: float) -> int:
        if not vals:
            return 0
        s = sorted(vals)
        return s[int(len(s) * q)]

    print("\n=== AES Toggle Signal Quality ===")
    print(f"Group A (T0[0..7] accessed):     n={len(a_tsc)}", end="")
    if a_tsc:
        print(f"  median={statistics.median(a_tsc):.0f}  mean={statistics.fmean(a_tsc):.0f}"
              f"  stdev={statistics.pstdev(a_tsc):.0f}  p10={pct(a_tsc,0.1)}  p90={pct(a_tsc,0.9)}")
    else:
        print()

    print(f"Group B (T0[128..255] accessed): n={len(b_tsc)}", end="")
    if b_tsc:
        print(f"  median={statistics.median(b_tsc):.0f}  mean={statistics.fmean(b_tsc):.0f}"
              f"  stdev={statistics.pstdev(b_tsc):.0f}  p10={pct(b_tsc,0.1)}  p90={pct(b_tsc,0.9)}")
    else:
        print()

    if a_tsc and b_tsc:
        sep = statistics.median(a_tsc) - statistics.median(b_tsc)
        pooled_std = ((statistics.pstdev(a_tsc)**2 + statistics.pstdev(b_tsc)**2) / 2) ** 0.5
        snr = abs(sep) / max(1.0, pooled_std)
        print(f"\nSeparation (A.median - B.median): {sep:.0f} TSC cycles")
        print(f"SNR (sep / pooled_stdev):          {snr:.3f}")

        print("\nDistribution (A):")
        _print_hist(a_tsc)
        print("Distribution (B):")
        _print_hist(b_tsc)

        if abs(sep) > 50 and snr > 0.5:
            print("\n[RESULT] Signal DETECTED — distributions are separable.")
        elif abs(sep) > 20:
            print("\n[RESULT] Weak signal — marginal separation.")
        else:
            print("\n[RESULT] No signal — distributions overlap.")

        result = {
            "n_a": len(a_tsc), "n_b": len(b_tsc),
            "median_a": float(statistics.median(a_tsc)),
            "median_b": float(statistics.median(b_tsc)),
            "mean_a": float(statistics.fmean(a_tsc)),
            "mean_b": float(statistics.fmean(b_tsc)),
            "stdev_a": float(statistics.pstdev(a_tsc)),
            "stdev_b": float(statistics.pstdev(b_tsc)),
            "separation_median": float(sep),
            "snr": float(snr),
        }
        if serial_log.exists():
            text = serial_log.read_text(errors="ignore")
            matches = DONE_RE.findall(text)
            if matches:
                iters, total_calls, loop_cycles, loop_ns, cyc_per_call, ns_per_call = matches[-1]
                result.update(
                    {
                        "guest_iters": int(iters),
                        "guest_total_aes_calls": int(total_calls),
                        "guest_loop_cycles": int(loop_cycles),
                        "guest_loop_ns": int(loop_ns),
                        "guest_cycles_per_call": float(cyc_per_call),
                        "guest_ns_per_call": float(ns_per_call),
                    }
                )
        write_json(outdir / "aes_toggle_analysis.json", result)

    if summary_path.exists():
        print(f"\n--- {summary_path} ---")
        print(summary_path.read_text())


def _print_hist(vals: list[int]) -> None:
    if not vals:
        return
    lo = min(vals)
    hi = max(vals)
    bucket_w = max(25, (hi - lo) // 16)
    buckets: dict[int, int] = {}
    for v in vals:
        k = ((v - lo) // bucket_w) * bucket_w + lo
        buckets[k] = buckets.get(k, 0) + 1
    for k in sorted(buckets)[:12]:
        bar = "#" * min(40, buckets[k] * 40 // max(buckets.values()))
        print(f"  [{k:5d}-{k+bucket_w-1:5d}]: {bar:40s} {buckets[k]}")


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="AES toggle signal validation")
    ap.add_argument("--iters", type=int, default=2000, help="AES iterations per group (total signals = iters*2)")
    ap.add_argument("--te0-file-offset", type=lambda x: int(x, 0), default=0xf60,
                    help="T0 file offset in OpenSSL library (default: 0xf60)")
    ap.add_argument("--outdir", default="")
    ap.add_argument("--skip-build", action="store_true")
    ap.add_argument("--qemu-cpu", type=int, default=32)
    ap.add_argument("--cpu-model", default="host,pmu=on")
    ap.add_argument("--guest-extra-cmdline", default="nokaslr norandmaps")
    ap.add_argument("--smp", default="1")
    ap.add_argument("--mem", default="4G")
    ap.add_argument("--vm-ready-timeout-s", type=int, default=300)
    ap.add_argument("--probe-mode", choices=["cacheable", "nocache"], default="cacheable")
    ap.add_argument("--probe-burst", type=int, default=1)
    ap.add_argument("--probe-delay-us", type=int, default=0)
    ap.add_argument("--probe-score-mode", choices=["mean", "max"], default="mean")
    ap.add_argument("--set-host-uc", action="store_true")
    ap.add_argument("--resctrl-enable", action="store_true")
    ap.add_argument("--resctrl-prefix", default="cohch6")
    ap.add_argument("--resctrl-host-mba", type=int, default=0, help="If >0, apply MBA percentage cap to host group.")
    return ap.parse_args()


def main() -> None:
    args = parse_args()
    require_root("[!] run_aes_toggle.py requires root.")

    outdir = Path(args.outdir).resolve() if args.outdir else timestamped_outdir_ch5("aes_toggle")
    outdir.mkdir(parents=True, exist_ok=True)
    print_banner("AES Toggle: RRFS cache coherence signal validation", outdir)

    ensure_artifacts(args.skip_build, outdir / "build_stage")
    collect_host_facts(outdir)

    vm_dir = outdir / "vm"
    proc = launch_vm(args, vm_dir)
    print(f"[run] VM launched (pid={proc.pid}), waiting for aes_toggle_done.txt ...")
    print(f"[run] Expected duration: ~{args.iters * 2 * 2 / 1000:.0f}s (rough estimate)")

    try:
        if bool(args.resctrl_enable):
            rec = apply_resctrl_partition(args, vm_dir, proc.pid)
            print(
                "[run] resctrl enabled: "
                f"host_mask={rec['host_mask_hex']} cvm_mask={rec['cvm_mask_hex']} "
                f"host_mba={rec.get('host_mba_percent')}"
            )
        done = wait_done(vm_dir, args.vm_ready_timeout_s)
        if not done:
            print(f"[run] Timeout waiting for done file. Check {vm_dir / 'qemu.log'}")
        else:
            print("[run] Done file received.")
        analyze(vm_dir, outdir)
        chown_to_sudo_user(outdir)
    finally:
        cleanup_resctrl(args)
        stop_proc(proc)


if __name__ == "__main__":
    main()
