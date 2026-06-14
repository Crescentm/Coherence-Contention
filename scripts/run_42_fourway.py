#!/usr/bin/env python3
"""
run_42_fourway.py — 实验 4.2.4: 四路对比

采集两组新数据（各 20k 样本）：
  H1_cont: cacheable + 每次探测前 CLFLUSH（仅竞争信号）
           guest probe_mode=contention，HR_MODE=contention_cacheable
  H1_cmb:  cacheable 无 CLFLUSH（一致性+竞争联合信号）
           guest probe_mode=contention_blind，HR_MODE=contention_cmb

H0 和 H1_coh 复用 §4.2.1（exp4_2_a）的 50k 数据，不重新采集。
"""
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


def resolve_ref_42a_dir(user_path: str) -> Path:
    if user_path:
        p = Path(user_path).expanduser().resolve()
        if not p.exists():
            raise SystemExit(f"[ref] --ref-42a-dir not found: {p}")
        return p

    cands = sorted((RESULT_CH4).glob("exp4_2_a_*"))
    cands = [p for p in cands if p.is_dir()]
    if not cands:
        raise SystemExit(
            "[ref] no exp4_2_a_* directory found under result/ch4; "
            "please pass --ref-42a-dir"
        )
    return cands[-1]


def run_case(
    outdir: Path,
    *,
    name: str,
    hr_mode: str,
    probe_mode: str,
    reps: int,
    victim_line: int,
    host_cpu: int,
    qemu_cpu: int,
    mem: str,
    smp: str,
    timeout_s: int,
):
    case_dir = outdir / name
    case_dir.mkdir(parents=True, exist_ok=True)
    sync_log = case_dir / "sync.log"
    qlog = case_dir / "qemu.log"
    done_file = case_dir / "contention_done.txt"

    for p in [sync_log, qlog, case_dir / "qemu_console.log",
              case_dir / "qemu.monitor", case_dir / "meta.txt",
              case_dir / "raw_h0_cycles.csv", case_dir / "raw_h1_cycles.csv",
              done_file]:
        p.unlink(missing_ok=True)
    sync_log.touch()

    preload_env = {
        "HR_MODE": hr_mode,
        "HR_REPS": str(reps),
        "HR_CPU": str(host_cpu),
        "HR_OUTDIR": str(case_dir),
        "HR_SYNC_LOG": str(sync_log),
        "LD_PRELOAD": str(PRELOAD_SO),
    }
    env = os.environ.copy()

    qemu_cmd = [
        "taskset", "-c", str(qemu_cpu),
        "env",
        *(f"{k}={v}" for k, v in preload_env.items()),
        str(QEMU_BIN),
        "-enable-kvm",
        "-cpu", "EPYC-v4",
        "-machine", "q35,smm=off",
        "-machine", "confidential-guest-support=sev0,vmport=off",
        "-machine", "memory-backend=ram1",
        "-smp", str(smp),
        "-m", str(mem),
        "-no-reboot",
        "-object", f"memory-backend-memfd,id=ram1,size={mem},share=true,prealloc=false",
        "-object", "sev-snp-guest,id=sev0,policy=0x30000,cbitpos=51,reduced-phys-bits=1",
        "-bios", str(OVMF_FD),
        "-kernel", str(GUEST_KERNEL),
        "-append",
        f"console=ttyS0 rdinit=/init panic=-1 quiet probe_mode={probe_mode} probe_dec_line={victim_line}",
        "-initrd", str(INITRAMFS),
        "-serial", f"file:{case_dir / 'qemu_console.log'}",
        "-debugcon", f"file:{sync_log}",
        "-nographic",
        "-monitor", f"unix:{case_dir / 'qemu.monitor'},server,nowait",
    ]

    print(f"\n[case] {name}: hr_mode={hr_mode} probe_mode={probe_mode}")
    with qlog.open("w") as fp:
        proc = subprocess.Popen(
            qemu_cmd,
            cwd=str(SRC_DIR),
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=fp,
            stderr=subprocess.STDOUT,
        )
        start = time.time()
        print(f"[case] qemu pid={proc.pid}, waiting for done...", end="", flush=True)
        while not done_file.exists():
            time.sleep(5)
            print(".", end="", flush=True)
            if proc.poll() is not None:
                break
            if time.time() - start >= timeout_s:
                print("\n[!] timeout")
                break
        print("")
        stop_proc(proc, timeout_s=10.0)

    if (case_dir / "raw_h1_cycles.csv").exists():
        print(f"[case] {name} done")
    else:
        print(f"[case] {name} WARNING: raw_h1_cycles.csv not found")


def main():
    ap = argparse.ArgumentParser(
        description="Experiment 4.2.4: four-way comparison (H1_cont + H1_cmb)."
    )
    ap.add_argument("--reps", type=int, default=20000)
    ap.add_argument("--victim-line", type=int, default=0)
    ap.add_argument("--host-cpu", type=int, default=33)
    ap.add_argument("--qemu-cpu", type=int, default=32)
    ap.add_argument("--mem", default="2G")
    ap.add_argument("--smp", default="1")
    ap.add_argument("--timeout", type=int, default=1800)
    ap.add_argument("--skip-build", action="store_true")
    ap.add_argument("--outdir", default="")
    # 可选：指定 §4.2.1 数据目录（H0 + H1_coh 复用）；默认自动选择最新 exp4_2_a_*
    ap.add_argument("--ref-42a-dir", default="",
                    help="§4.2.1 数据目录（含 raw_h0_cycles.csv / raw_h1_cycles.csv）")
    args = ap.parse_args()

    require_root("[!] Please run as root, e.g. sudo -E python3 scripts/run_42_fourway.py")
    outdir = (
        Path(args.outdir).resolve()
        if args.outdir
        else timestamped_outdir("exp4_2_fourway", RESULT_CH4)
    )
    outdir.mkdir(parents=True, exist_ok=True)
    print_banner("Experiment 4.2.4: four-way comparison", outdir)

    ensure_artifacts(args.skip_build, outdir)
    ensure_runtime_paths()

    common = dict(
        reps=args.reps,
        victim_line=args.victim_line,
        host_cpu=args.host_cpu,
        qemu_cpu=args.qemu_cpu,
        mem=args.mem,
        smp=args.smp,
        timeout_s=args.timeout,
    )

    # H1_cont: cacheable + clflush，仅竞争信号
    run_case(outdir, name="h1_cont", hr_mode="contention_cacheable",
             probe_mode="contention", **common)

    # H1_cmb: cacheable 无 clflush，一致性+竞争联合信号
    run_case(outdir, name="h1_cmb", hr_mode="contention_cmb",
             probe_mode="contention_blind", **common)

    # 复制顶层文件供分析脚本直接使用
    copies = [
        (outdir / "h1_cont" / "raw_h1_cycles.csv", outdir / "raw_h1_cont_cycles.csv"),
        (outdir / "h1_cmb" / "raw_h1_cycles.csv", outdir / "raw_h1_cmb_cycles.csv"),
    ]
    for src, dst in copies:
        if src.exists():
            shutil.copy2(src, dst)

    # 复用 §4.2.1 的 H0 和 H1_coh（不重新采集）
    ref = resolve_ref_42a_dir(args.ref_42a_dir)
    print(f"[ref] using 4.2.1 dataset: {ref}")
    for fname, dst_name in [
        ("raw_h0_cycles.csv", "raw_h0_cycles.csv"),
        ("raw_h1_cycles.csv", "raw_h1_coh_cycles.csv"),
    ]:
        src = ref / fname
        if not src.exists():
            raise SystemExit(f"[ref] missing required file: {src}")
        shutil.copy2(src, outdir / dst_name)
        print(f"[ref] copied {src} -> {outdir / dst_name}")

    chown_to_sudo_user(outdir)
    print("\n=== 4.2.4 fourway completed ===")
    print(f"data dir: {outdir}")
    print(
        "analysis: "
        f"python3 {SRC_DIR / 'analyze' / 'exp42_fourway_analysis.py'} --dir {outdir}"
    )


if __name__ == "__main__":
    main()
