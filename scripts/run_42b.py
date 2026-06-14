#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
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


def main():
    ap = argparse.ArgumentParser(
        description="Experiment 4.2-B: pure DRAM contention signal capture."
    )
    ap.add_argument("--reps", type=int, default=50000)
    ap.add_argument("--victim-line", type=int, default=0)
    ap.add_argument("--host-cpu", type=int, default=33)
    ap.add_argument("--qemu-cpu", type=int, default=32)
    ap.add_argument("--mem", default="2G")
    ap.add_argument("--smp", default="1")
    ap.add_argument("--timeout", type=int, default=1800)
    ap.add_argument("--skip-build", action="store_true")
    ap.add_argument("--outdir", default="")
    args = ap.parse_args()

    require_root("[!] Please run as root, e.g. sudo -E python3 scripts/run_42b.py")
    outdir = (
        Path(args.outdir).resolve()
        if args.outdir
        else timestamped_outdir("exp4_2_b", RESULT_CH4)
    )
    outdir.mkdir(parents=True, exist_ok=True)
    print_banner(f"Experiment 4.2-B: DRAM contention ({args.reps} reps)", outdir)

    ensure_artifacts(args.skip_build, outdir)
    ensure_runtime_paths()

    sync_log = outdir / "sync.log"
    qemu_log = outdir / "qemu.log"
    qemu_console = outdir / "qemu_console.log"
    done_file = outdir / "contention_done.txt"

    stale = [
        sync_log,
        qemu_log,
        qemu_console,
        outdir / "qemu.monitor",
        done_file,
        outdir / "meta.txt",
        outdir / "raw_h0_cycles.csv",
        outdir / "raw_h1_cycles.csv",
    ]
    for p in stale:
        p.unlink(missing_ok=True)
    sync_log.touch()

    env = os.environ.copy()
    env["HR_MODE"] = "contention"
    env["HR_REPS"] = str(args.reps)
    env["HR_CPU"] = str(args.host_cpu)
    env["HR_OUTDIR"] = str(outdir)
    env["HR_SYNC_LOG"] = str(sync_log)
    env["LD_PRELOAD"] = str(PRELOAD_SO)

    qemu_cmd = [
        "taskset",
        "-c",
        str(args.qemu_cpu),
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
        str(args.smp),
        "-m",
        str(args.mem),
        "-no-reboot",
        "-object",
        f"memory-backend-memfd,id=ram1,size={args.mem},share=true,prealloc=false",
        "-object",
        "sev-snp-guest,id=sev0,policy=0x30000,cbitpos=51,reduced-phys-bits=1",
        "-bios",
        str(OVMF_FD),
        "-kernel",
        str(GUEST_KERNEL),
        "-append",
        f"console=ttyS0 rdinit=/init panic=-1 quiet probe_mode=contention probe_dec_line={args.victim_line}",
        "-initrd",
        str(INITRAMFS),
        "-serial",
        f"file:{qemu_console}",
        "-debugcon",
        f"file:{sync_log}",
        "-nographic",
        "-monitor",
        f"unix:{outdir / 'qemu.monitor'},server,nowait",
    ]

    print("[run] launching qemu...")
    with qemu_log.open("w") as fp:
        proc = subprocess.Popen(
            qemu_cmd,
            cwd=str(SRC_DIR),
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=fp,
            stderr=subprocess.STDOUT,
        )
        print(f"[run] qemu pid={proc.pid}")
        start = time.time()
        print("[run] waiting for contention_done.txt", end="", flush=True)
        while not done_file.exists():
            time.sleep(5)
            print(".", end="", flush=True)
            if proc.poll() is not None:
                break
            if time.time() - start >= args.timeout:
                print("\n[!] timeout, stopping qemu")
                break
        print("")
        stop_proc(proc, timeout_s=10.0)

    chown_to_sudo_user(outdir)
    print("\n=== 4.2-B completed ===")
    print(f"data dir: {outdir}")
    print(
        "analysis: "
        f"python3 {SRC_DIR / 'analyze' / 'exp42b_analysis.py'} --dir {outdir} --out {outdir}"
    )


if __name__ == "__main__":
    main()
