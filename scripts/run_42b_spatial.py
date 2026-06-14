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


def make_affinity_preexec(cpu: int):
    if cpu < 0:
        return None

    def _fn() -> None:
        os.sched_setaffinity(0, {cpu})

    return _fn


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Experiment 4.2-B-spatial: scan the spatial extent of contention signal."
    )
    ap.add_argument("--reps", type=int, default=3000)
    ap.add_argument("--victim-line", type=int, default=32)
    ap.add_argument("--host-cpu", type=int, default=33)
    ap.add_argument("--qemu-cpu", type=int, default=32)
    ap.add_argument("--mem", default="2G")
    ap.add_argument("--smp", default="1")
    ap.add_argument("--timeout", type=int, default=3600)
    ap.add_argument("--skip-build", action="store_true")
    ap.add_argument("--outdir", default="")
    args = ap.parse_args()

    require_root("[!] Please run as root, e.g. sudo -E python3 scripts/run_42b_spatial.py")
    outdir = (
        Path(args.outdir).resolve()
        if args.outdir
        else timestamped_outdir("exp4_2_b_spatial", RESULT_CH4)
    )
    outdir.mkdir(parents=True, exist_ok=True)
    print_banner(
        f"Experiment 4.2-B spatial response (reps={args.reps}, victim_line={args.victim_line})",
        outdir,
    )

    ensure_artifacts(args.skip_build, outdir)
    ensure_runtime_paths()

    sync_log = outdir / "sync.log"
    qemu_log = outdir / "qemu.log"
    done_file = outdir / "contention_spatial_done.txt"
    env_file = outdir / "experiment_env.txt"
    for p in [
        sync_log,
        qemu_log,
        outdir / "qemu_console.log",
        outdir / "qemu.monitor",
        done_file,
        env_file,
        outdir / "meta.txt",
        outdir / "spatial_scan.csv",
        outdir / "spatial_scan_raw.csv",
    ]:
        p.unlink(missing_ok=True)
    sync_log.touch()

    env_file.write_text(
        "\n".join(
            [
                "experiment=4.2-B-spatial",
                "goal=measure_spatial_response_of_contention_signal",
                "guest_probe_mode=contention_spatial",
                "host_runner_mode=contention_spatial",
                "host_probe_mode=ciphertext-nocache",
                "host_probe_mapping=decrypted_nocache",
                "host_h0_definition=probe_other_page_same_offset_before_sync",
                "host_h1_definition=probe_target_page_same_offset_after_sync_before_ack",
                "guest_h0_definition=idle_then_signal",
                "guest_h1_definition=clflush_plus_load_then_signal_and_hammer_until_ack",
                f"victim_line={args.victim_line}",
                f"reps={args.reps}",
                f"host_cpu={args.host_cpu}",
                f"qemu_cpu={args.qemu_cpu}",
                f"mem={args.mem}",
                f"smp={args.smp}",
            ]
        )
        + "\n"
    )

    env = os.environ.copy()
    env["HR_MODE"] = "contention_spatial"
    env["HR_REPS"] = str(args.reps)
    env["HR_CPU"] = str(args.host_cpu)
    env["HR_OUTDIR"] = str(outdir)
    env["HR_SYNC_LOG"] = str(sync_log)
    env["LD_PRELOAD"] = str(PRELOAD_SO)

    qemu_cmd = [
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
        f"console=ttyS0 rdinit=/init panic=-1 quiet probe_mode=contention_spatial probe_dec_line={args.victim_line}",
        "-initrd",
        str(INITRAMFS),
        "-serial",
        f"file:{outdir / 'qemu_console.log'}",
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
            preexec_fn=make_affinity_preexec(args.qemu_cpu),
        )
        start = time.time()
        print(f"[run] qemu pid={proc.pid}, waiting for contention_spatial_done.txt", end="", flush=True)
        while not done_file.exists():
            time.sleep(5)
            print(".", end="", flush=True)
            if proc.poll() is not None:
                break
            if time.time() - start >= args.timeout:
                print("\n[!] timeout")
                break
        print("")
        stop_proc(proc, timeout_s=10.0)

    if not done_file.exists():
        raise SystemExit("[run] contention_spatial_done.txt not found")

    chown_to_sudo_user(outdir)
    print("\n=== 4.2-B spatial completed ===")
    print(f"data dir: {outdir}")
    print(
        "analysis: "
        f"python3 {SRC_DIR / 'analyze' / 'exp42b_spatial_analysis.py'} --dir {outdir}"
    )


if __name__ == "__main__":
    main()
