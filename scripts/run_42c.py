#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import time
from pathlib import Path

from experiment_common import (
    GUEST_KERNEL,
    INITRAMFS,
    OVMF_FD,
    PRELOAD_SO,
    QEMU_BIN,
    RESULT_CH4,
    SRC_DIR,
    chown_to_sudo_user,
    ensure_artifacts,
    ensure_runtime_paths,
    print_banner,
    require_root,
    stop_proc,
    timestamped_outdir,
)


def wait_for_samples(csv_path: Path, reps: int, proc: subprocess.Popen, timeout_s: int) -> bool:
    need = reps + 1
    start = time.time()
    while time.time() - start < timeout_s:
        if csv_path.exists():
            try:
                lines = sum(1 for _ in csv_path.open("r"))
            except OSError:
                lines = 0
            if lines >= need:
                return True
        if proc.poll() is not None:
            return False
        time.sleep(1)
    return False


def run_case(
    outdir: Path,
    *,
    name: str,
    probe_mode: str,
    page_kind: str,
    nocache: int,
    reps: int,
    victim_line: int,
    host_cpu: int,
    qemu_cpu: int,
):
    case_dir = outdir / name
    case_dir.mkdir(parents=True, exist_ok=True)
    sync_log = case_dir / "sync.log"
    qlog = case_dir / "qemu.log"
    raw = case_dir / "raw_cycles.csv"

    for p in [
        sync_log,
        qlog,
        case_dir / "qemu_console.log",
        case_dir / "qemu.monitor",
        case_dir / "meta.txt",
        raw,
    ]:
        p.unlink(missing_ok=True)
    sync_log.touch()

    hr_mode = "blind" if probe_mode == "blind" else "single"
    env = os.environ.copy()
    env["HR_MODE"] = hr_mode
    env["HR_NOCACHE"] = str(nocache)
    env["HR_REPS"] = str(reps)
    env["HR_CPU"] = str(host_cpu)
    env["HR_VICTIM_LINE"] = str(victim_line)
    env["HR_PAGE_KIND"] = page_kind
    env["HR_OUTDIR"] = str(case_dir)
    env["HR_SYNC_LOG"] = str(sync_log)
    env["HR_RAW_FILE"] = str(raw)
    env["LD_PRELOAD"] = str(PRELOAD_SO)

    qemu_cmd = [
        "taskset",
        "-c",
        str(qemu_cpu),
        str(QEMU_BIN),
        "-enable-kvm",
        "-cpu",
        "EPYC-v4",
        "-machine",
        "q35,smm=off",
        "-machine",
        "confidential-guest-support=sev0,vmport=off",
        "-machine",
        "memory-backend=ram1",
        "-smp",
        "1",
        "-m",
        "2G",
        "-no-reboot",
        "-object",
        "memory-backend-memfd,id=ram1,size=2G,share=true,prealloc=false",
        "-object",
        "sev-snp-guest,id=sev0,policy=0x30000,cbitpos=51,reduced-phys-bits=1",
        "-bios",
        str(OVMF_FD),
        "-kernel",
        str(GUEST_KERNEL),
        "-append",
        f"console=ttyS0 rdinit=/init panic=-1 quiet probe_mode={probe_mode} probe_dec_line={victim_line}",
        "-initrd",
        str(INITRAMFS),
        "-serial",
        f"file:{case_dir / 'qemu_console.log'}",
        "-debugcon",
        f"file:{sync_log}",
        "-nographic",
        "-monitor",
        f"unix:{case_dir / 'qemu.monitor'},server,nowait",
    ]

    print(f"\n[case] {name}: mode={probe_mode} page={page_kind} nocache={nocache}")
    with qlog.open("w") as fp:
        proc = subprocess.Popen(
            qemu_cmd,
            cwd=str(SRC_DIR),
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=fp,
            stderr=subprocess.STDOUT,
        )
        ok = wait_for_samples(raw, reps, proc, timeout_s=1800)
        if ok:
            print(f"[case] {name} collected {reps} samples")
        else:
            print(f"[case] {name} did not reach expected samples")
        stop_proc(proc, timeout_s=10.0)


def main():
    ap = argparse.ArgumentParser(
        description="Experiment 4.2-C: combined coherence and contention."
    )
    ap.add_argument("--reps", type=int, default=20000)
    ap.add_argument("--victim-line", type=int, default=0)
    ap.add_argument("--host-cpu", type=int, default=33)
    ap.add_argument("--qemu-cpu", type=int, default=32)
    ap.add_argument("--skip-build", action="store_true")
    ap.add_argument("--outdir", default="")
    args = ap.parse_args()

    require_root("[!] Please run as root, e.g. sudo -E python3 scripts/run_42c.py")
    outdir = (
        Path(args.outdir).resolve()
        if args.outdir
        else timestamped_outdir("exp4_2_c", RESULT_CH4)
    )
    outdir.mkdir(parents=True, exist_ok=True)
    print_banner("Experiment 4.2-C: combined coherence and contention", outdir)

    ensure_artifacts(args.skip_build, outdir)
    ensure_runtime_paths()

    run_case(
        outdir,
        name="h0_baseline",
        probe_mode="sync",
        page_kind="other",
        nocache=0,
        reps=args.reps,
        victim_line=args.victim_line,
        host_cpu=args.host_cpu,
        qemu_cpu=args.qemu_cpu,
    )
    run_case(
        outdir,
        name="h1_coherence_only",
        probe_mode="sync",
        page_kind="same",
        nocache=0,
        reps=args.reps,
        victim_line=args.victim_line,
        host_cpu=args.host_cpu,
        qemu_cpu=args.qemu_cpu,
    )
    run_case(
        outdir,
        name="h1_combined",
        probe_mode="blind",
        page_kind="same",
        nocache=0,
        reps=args.reps,
        victim_line=args.victim_line,
        host_cpu=args.host_cpu,
        qemu_cpu=args.qemu_cpu,
    )

    copies = [
        (outdir / "h0_baseline" / "raw_cycles.csv", outdir / "raw_h0_cycles.csv"),
        (
            outdir / "h1_coherence_only" / "raw_cycles.csv",
            outdir / "raw_h1_coherence_cycles.csv",
        ),
        (outdir / "h1_combined" / "raw_cycles.csv", outdir / "raw_h1_cycles.csv"),
    ]
    for src, dst in copies:
        if src.exists():
            shutil.copy2(src, dst)

    chown_to_sudo_user(outdir)
    print("\n=== 4.2-C completed ===")
    print(f"data dir: {outdir}")
    print(
        "analysis: "
        f"python3 {SRC_DIR / 'analyze' / 'exp42c_analysis.py'} --dir {outdir}"
    )


if __name__ == "__main__":
    main()
