#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import time
from pathlib import Path

from experiment_common import (
    FR_VERIFY_BIN,
    GUEST_KERNEL,
    INITRAMFS,
    OVMF_FD,
    QEMU_BIN,
    RESULT_CH4,
    RUN_EXPERIMENT,
    SRC_DIR,
    ensure_artifacts,
    ensure_runtime_paths,
    print_banner,
    require_root,
    run_checked,
    run_qemu_background,
    stop_proc,
    timestamped_outdir,
)


def run_44a(result_base: Path, reps: int, qemu_cpu: int, host_cpu: int, mem: str, smp: str, forced_iters: int):
    outdir = result_base / "exp4_4_a"
    outdir.mkdir(parents=True, exist_ok=True)
    print_banner("Experiment 4.4-A: Prime+Count plain vs SNP", outdir)

    def run_one(out_sub: str, no_snp: bool):
        run_dir = outdir / out_sub
        run_dir.mkdir(parents=True, exist_ok=True)
        env = os.environ.copy()
        env["HR_PC_FORCED_ITERS"] = str(forced_iters)
        cmd = [
            "python3",
            str(RUN_EXPERIMENT),
            "--pc-mode",
            "--reps",
            str(reps),
            "--pc-line",
            "37",
            "--pc-probe-cpu",
            str(host_cpu + 1),
            "--outdir",
            str(run_dir),
            "--qemu-cpu",
            str(qemu_cpu),
            "--host-cpu",
            str(host_cpu),
            "--mem",
            str(mem),
            "--smp",
            str(smp),
            "--skip-build",
        ]
        if no_snp:
            cmd.append("--no-snp")
        run_checked(cmd, cwd=SRC_DIR, env=env)

    run_one("plain_vm", no_snp=True)
    run_one("snp_vm", no_snp=False)

    print("\n=== 4.4-A completed ===")
    print(f"analysis: python3 {SRC_DIR / 'analyze' / 'exp44_analysis.py'} --exp a --data-dir {outdir}")


def run_44b(result_base: Path, qemu_cpu: int, mem: str, smp: str):
    outdir = result_base / "exp4_4_b"
    outdir.mkdir(parents=True, exist_ok=True)
    print_banner("Experiment 4.4-B: Flush+Reload negative validation", outdir)

    run_checked(["make", "fr_verify"], cwd=SRC_DIR)
    if not FR_VERIFY_BIN.exists():
        raise SystemExit(f"[4.4-B] missing binary: {FR_VERIFY_BIN}")

    result_txt = outdir / "fr_verify_result.txt"
    run_checked([str(FR_VERIFY_BIN), str(result_txt)], cwd=SRC_DIR, check=False)

    vm_dir = outdir / "vm_run"
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
        str(smp),
        "-m",
        str(mem),
        "-no-reboot",
        "-object",
        f"memory-backend-memfd,id=ram1,size={mem},share=true,prealloc=false",
        "-object",
        "sev-snp-guest,id=sev0,policy=0x30000,cbitpos=51,reduced-phys-bits=1",
        "-bios",
        str(OVMF_FD),
        "-kernel",
        str(GUEST_KERNEL),
        "-initrd",
        str(INITRAMFS),
        "-append",
        "console=ttyS0 rdinit=/init panic=-1 quiet probe_mode=hammer64 probe_dec_line=0",
        "-serial",
        f"file:{vm_dir / 'qemu_console.log'}",
        "-debugcon",
        f"file:{vm_dir / 'debugcon.log'}",
        "-nographic",
        "-monitor",
        f"unix:{vm_dir / 'qemu.monitor'},server,nowait",
    ]

    proc = run_qemu_background(qemu_cmd, log_path=vm_dir / "qemu.log", cwd=SRC_DIR)
    time.sleep(8)
    result_vm_txt = outdir / "fr_verify_with_vm.txt"
    run_checked([str(FR_VERIFY_BIN), str(result_vm_txt)], cwd=SRC_DIR, check=False)
    maps = Path(f"/proc/{proc.pid}/maps")
    with result_vm_txt.open("a") as fp:
        fp.write("\n--- QEMU process memory access attempt ---\n")
        fp.write(f"QEMU PID: {proc.pid}\n")
        if maps.exists():
            try:
                lines = maps.read_text().splitlines()[:20]
                fp.write("\n".join(lines) + "\n")
            except OSError as exc:
                fp.write(f"read maps failed: {exc}\n")
        else:
            fp.write("cannot access qemu maps\n")
    stop_proc(proc, timeout_s=10.0)

    print("\n=== 4.4-B completed ===")
    print(f"results:\n  {result_txt}\n  {result_vm_txt}")
    print(f"analysis: python3 {SRC_DIR / 'analyze' / 'exp44_analysis.py'} --exp b --data-dir {outdir}")


def run_44c(result_base: Path, reps: int, host_cpu: int, qemu_cpu: int):
    outdir = result_base / "exp4_4_c"
    outdir.mkdir(parents=True, exist_ok=True)
    print_banner("Experiment 4.4-C: three-method same-platform comparison", outdir)

    src_44a = result_base / "exp4_4_a"
    src_42a = result_base / "exp4_2_a"
    src_42b = result_base / "exp4_2_b"

    pc_snp = src_44a / "snp_vm"
    pc_plain = src_44a / "plain_vm"
    (outdir / "prime_count_snp").mkdir(parents=True, exist_ok=True)
    (outdir / "prime_count_plain").mkdir(parents=True, exist_ok=True)
    for f in ["raw_h0_counts.csv", "raw_h1_counts.csv", "meta.txt"]:
        if (pc_snp / f).exists():
            shutil.copy2(pc_snp / f, outdir / "prime_count_snp" / f)
        if (pc_plain / f).exists():
            shutil.copy2(pc_plain / f, outdir / "prime_count_plain" / f)

    coh = outdir / "coherence_eviction"
    coh.mkdir(parents=True, exist_ok=True)
    if (src_42a / "raw_h0_cycles.csv").exists():
        shutil.copy2(src_42a / "raw_h0_cycles.csv", coh / "raw_h0_cycles.csv")
        shutil.copy2(src_42a / "raw_h1_cycles.csv", coh / "raw_h1_cycles.csv")
    else:
        print("[4.4-C] warning: missing 4.2-A data, run scripts/run_42a.py first")

    memc = outdir / "mem_contention"
    memc.mkdir(parents=True, exist_ok=True)
    if (src_42b / "raw_h0_cycles.csv").exists():
        shutil.copy2(src_42b / "raw_h0_cycles.csv", memc / "raw_h0_cycles.csv")
        shutil.copy2(src_42b / "raw_h1_cycles.csv", memc / "raw_h1_cycles.csv")
    else:
        print("[4.4-C] warning: missing 4.2-B data, run scripts/run_42b.py first")

    meta = {
        "experiment": "4.4-C",
        "description": "Prime+Count / coherence eviction / memory contention comparison",
        "methods": {
            "prime_count_plain": str(outdir / "prime_count_plain"),
            "prime_count_snp": str(outdir / "prime_count_snp"),
            "coherence_eviction": str(outdir / "coherence_eviction"),
            "mem_contention": str(outdir / "mem_contention"),
        },
        "reps": reps,
        "host_cpu": host_cpu,
        "qemu_cpu": qemu_cpu,
    }
    (outdir / "meta.json").write_text(json.dumps(meta, indent=2) + "\n")

    print("\n=== 4.4-C completed ===")
    print(f"analysis: python3 {SRC_DIR / 'analyze' / 'exp44_analysis.py'} --exp c --data-dir {outdir}")


def main():
    ap = argparse.ArgumentParser(
        description="Experiment 4.4 orchestration in Python (A/B/C/all)."
    )
    ap.add_argument("sub", nargs="?", default="all", choices=["a", "b", "c", "all"])
    ap.add_argument("--reps", type=int, default=50000)
    ap.add_argument("--host-cpu", type=int, default=33)
    ap.add_argument("--qemu-cpu", type=int, default=32)
    ap.add_argument("--mem", default="2G")
    ap.add_argument("--smp", default="1")
    ap.add_argument("--pc-forced-iters", type=int, default=4000)
    ap.add_argument("--skip-build", action="store_true")
    ap.add_argument("--result-base", default="")
    args = ap.parse_args()

    require_root("[!] Please run as root, e.g. sudo -E python3 scripts/run_44.py all")
    result_base = (
        Path(args.result_base).resolve()
        if args.result_base
        else timestamped_outdir("exp4_4", RESULT_CH4)
    )
    print_banner(f"Experiment 4.4 (sub={args.sub})", result_base)

    ensure_artifacts(args.skip_build, result_base / "exp4_4_build")
    ensure_runtime_paths()

    if args.sub in ("a", "all"):
        run_44a(result_base, args.reps, args.qemu_cpu, args.host_cpu, args.mem, args.smp, args.pc_forced_iters)
    if args.sub in ("b", "all"):
        run_44b(result_base, args.qemu_cpu, args.mem, args.smp)
    if args.sub in ("c", "all"):
        run_44c(result_base, args.reps, args.host_cpu, args.qemu_cpu)

    print("\n=== 4.4 finished ===")
    print(
        "analysis: "
        f"python3 {SRC_DIR / 'analyze' / 'exp44_analysis.py'} --exp all --data-dir {result_base}"
    )


if __name__ == "__main__":
    main()
