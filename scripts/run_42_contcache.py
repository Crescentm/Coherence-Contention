#!/usr/bin/env python3
"""
run_42_contcache.py — 实验 4.2.3.2: Cacheable 路径竞争信号

协议：
  H0: guest 以 contention 模式运行，宿主机测量 other_gpa（guest 不访问该行）
      每次探测前 CLFLUSH（排除一致性信号），只保留竞争信号基线
  H1: 同一 guest，宿主机测量 page_gpa（guest 刚完成 CLFLUSH+load）
      每次探测前 CLFLUSH，只保留竞争信号

两组数据在同一次 QEMU 运行中采集（HR_MODE=contention_cacheable）。
"""
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
        description="Experiment 4.2.3.2: cacheable-path contention signal."
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

    require_root("[!] Please run as root, e.g. sudo -E python3 scripts/run_42_contcache.py")
    outdir = (
        Path(args.outdir).resolve()
        if args.outdir
        else timestamped_outdir("exp4_2_contcache", RESULT_CH4)
    )
    outdir.mkdir(parents=True, exist_ok=True)
    print_banner(
        f"Experiment 4.2.3.2: cacheable contention ({args.reps} reps)", outdir
    )

    ensure_artifacts(args.skip_build, outdir)
    ensure_runtime_paths()

    sync_log = outdir / "sync.log"
    qemu_log = outdir / "qemu.log"
    done_file = outdir / "contention_done.txt"
    heartbeat_file = outdir / "contention_heartbeat.txt"
    lock_file = outdir / ".hr_preload.lock"

    for p in [sync_log, qemu_log, done_file, outdir / "meta.txt",
              outdir / "raw_h0_cycles.csv", outdir / "raw_h1_cycles.csv",
              heartbeat_file, lock_file]:
        p.unlink(missing_ok=True)
    sync_log.touch()

    preload_env = {
        "HR_MODE": "contention_cacheable",
        "HR_REPS": str(args.reps),
        "HR_CPU": str(args.host_cpu),
        "HR_OUTDIR": str(outdir),
        "HR_SYNC_LOG": str(sync_log),
        "LD_PRELOAD": str(PRELOAD_SO),
    }
    env = os.environ.copy()

    qemu_cmd = [
        "taskset", "-c", str(args.qemu_cpu),
        "env",
        *(f"{k}={v}" for k, v in preload_env.items()),
        str(QEMU_BIN),
        "-enable-kvm",
        "-cpu", "EPYC-v4",
        "-machine", "q35,smm=off",
        "-machine", "confidential-guest-support=sev0,vmport=off",
        "-machine", "memory-backend=ram1",
        "-smp", str(args.smp),
        "-m", str(args.mem),
        "-no-reboot",
        "-object", f"memory-backend-memfd,id=ram1,size={args.mem},share=true,prealloc=false",
        "-object", "sev-snp-guest,id=sev0,policy=0x30000,cbitpos=51,reduced-phys-bits=1",
        "-bios", str(OVMF_FD),
        "-kernel", str(GUEST_KERNEL),
        "-append",
        f"console=ttyS0 rdinit=/init panic=-1 quiet probe_mode=contention probe_dec_line={args.victim_line}",
        "-initrd", str(INITRAMFS),
        "-serial", f"file:{outdir / 'qemu_console.log'}",
        "-debugcon", f"file:{sync_log}",
        "-nographic",
        "-monitor", f"unix:{outdir / 'qemu.monitor'},server,nowait",
    ]

    print("[run] launching qemu (contention_cacheable mode)...")
    timed_out = False
    qemu_exited_early = False
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
                qemu_exited_early = True
                break
            if time.time() - start >= args.timeout:
                print("\n[!] timeout, stopping qemu")
                timed_out = True
                break
        print("")
        stop_proc(proc, timeout_s=10.0)

    def _tail(path: Path, n: int = 80) -> str:
        if not path.exists():
            return f"<missing: {path}>"
        lines = path.read_text(errors="replace").splitlines()
        return "\n".join(lines[-n:])

    if not done_file.exists():
        print("[error] contention_done.txt not found.")
        print("[error] qemu.log tail:")
        print(_tail(qemu_log))
        print("[error] sync.log tail:")
        print(_tail(sync_log))
        print("[error] contention_heartbeat.txt tail:")
        print(_tail(heartbeat_file))
        reason = "timeout" if timed_out else "qemu exited before done"
        raise SystemExit(f"[run] failed: {reason}")

    done_text = done_file.read_text(errors="replace")
    done_kv: dict[str, str] = {}
    for line in done_text.splitlines():
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        done_kv[k.strip()] = v.strip()

    if done_kv.get("status") == "error":
        print("[error] host runner reported error in contention_done.txt")
        print(done_text)
        print("[error] qemu.log tail:")
        print(_tail(qemu_log))
        print("[error] sync.log tail:")
        print(_tail(sync_log))
        print("[error] contention_heartbeat.txt tail:")
        print(_tail(heartbeat_file))
        raise SystemExit(
            f"[run] failed: host runner error ({done_kv.get('error_reason', 'unknown')})"
        )

    if qemu_exited_early and done_kv.get("status", "ok") != "ok":
        raise SystemExit("[run] failed: qemu exited early without successful status")

    chown_to_sudo_user(outdir)
    print("\n=== 4.2.3.2 contcache completed ===")
    print(f"data dir: {outdir}")
    print(f"heartbeat: {heartbeat_file}")
    print(
        "analysis: "
        f"python3 {SRC_DIR / 'analyze' / 'exp42_contcache_analysis.py'} --dir {outdir}"
    )


if __name__ == "__main__":
    main()
