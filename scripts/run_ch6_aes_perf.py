#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
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


AES_PERF_RE = re.compile(r"^(blocks|total_cycles|total_ns|cycles_per_call|ns_per_call|throughput_ops_per_s|metric_kind|sink)=(.+)$")


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Chapter 6 pure AES benchmark under defense configurations.")
    ap.add_argument("--outdir", default="")
    ap.add_argument("--skip-build", action="store_true")
    ap.add_argument("--initrd", default="", help="Optional initrd override. Defaults to experiment_common.INITRAMFS.")
    ap.add_argument("--qemu-cpu", type=int, default=48)
    ap.add_argument("--cpu-model", default="host,pmu=on")
    ap.add_argument("--guest-extra-cmdline", default="nokaslr norandmaps")
    ap.add_argument("--smp", default="1")
    ap.add_argument("--mem", default="4G")
    ap.add_argument("--vm-ready-timeout-s", type=int, default=180)
    ap.add_argument("--blocks", type=int, default=20000000)
    ap.add_argument("--resctrl-enable", action="store_true")
    ap.add_argument("--resctrl-prefix", default="ch6perf")
    ap.add_argument("--resctrl-host-mba", type=int, default=0)
    return ap.parse_args()


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
    initrd_path = Path(args.initrd).resolve() if str(args.initrd).strip() else INITRAMFS
    for p, name in [(qemu_bin, "QEMU"), (ovmf_fd, "OVMF"), (GUEST_KERNEL, "kernel"), (initrd_path, "initramfs")]:
        if not p.exists():
            raise SystemExit(f"[env] {name} not found: {p}")

    aes_perf_args = f"--blocks_{int(args.blocks)}"
    append_parts = [
        "console=ttyS0",
        "rdinit=/init",
        "panic=-1",
        "quiet",
        "probe_mode=aes_perf",
        f"probe_aes_perf_args={aes_perf_args}",
    ]
    extra = str(getattr(args, "guest_extra_cmdline", "")).strip()
    if extra:
        append_parts.append(extra)
    append = " ".join(p for p in append_parts if p)

    env = os.environ.copy()
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
        "-initrd", str(initrd_path),
        "-append", append,
        "-serial", f"file:{vm_dir / 'qemu_console.log'}",
        "-nographic",
    ]

    qlog = (vm_dir / "qemu.log").open("w")
    proc = subprocess.Popen(
        qemu_cmd,
        cwd=str(SRC_DIR),
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=qlog,
        stderr=subprocess.STDOUT,
        preexec_fn=make_affinity_preexec(args.qemu_cpu),
        start_new_session=True,
    )
    return proc


def wait_perf_output(serial_log: Path, timeout_s: int) -> dict[str, str] | None:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if serial_log.exists():
            text = serial_log.read_text(errors="ignore")
            vals: dict[str, str] = {}
            for raw in text.splitlines():
                m = AES_PERF_RE.match(raw.strip())
                if m:
                    vals[m.group(1)] = m.group(2).strip()
            if "cycles_per_call" in vals and "ns_per_call" in vals:
                return vals
        time.sleep(1.0)
    return None


def apply_resctrl_partition(args: argparse.Namespace, vm_dir: Path, qemu_pid: int) -> dict:
    prefix = str(args.resctrl_prefix or "ch6perf")
    rc.cleanup_groups(prefix)
    rc.ensure_resctrl_mounted()
    cbm_mask = rc.read_l3_cbm_mask()
    host_mask, cvm_mask = rc.split_cbm_mask(cbm_mask)
    host_group = rc.create_group(
        f"{prefix}_host",
        l3_mask=host_mask,
        mba_percent=(int(args.resctrl_host_mba) if int(args.resctrl_host_mba) > 0 else None),
    )
    cvm_group = rc.create_group(f"{prefix}_cvm", l3_mask=cvm_mask, mba_percent=100)
    vcpu_tids, tasks = rc.wait_for_vcpu_tids(qemu_pid, timeout_s=15.0)
    all_tids = [tid for tid, _comm in tasks]
    host_tids = rc.filter_live_tids([tid for tid in all_tids if tid not in vcpu_tids])
    vcpu_tids = rc.filter_live_tids(vcpu_tids)
    if not vcpu_tids:
        thread_dump = ", ".join(f"{tid}:{comm}" for tid, comm in tasks)
        raise SystemExit(f"[resctrl] failed to identify vCPU threads; threads={thread_dump}")
    rc.assign_tids(host_group, host_tids)
    rc.assign_tids(cvm_group, vcpu_tids)
    rec = {
        "enabled": True,
        "cbm_mask_hex": f"0x{cbm_mask:x}",
        "host_mask_hex": f"0x{host_mask:x}",
        "cvm_mask_hex": f"0x{cvm_mask:x}",
        "host_group": str(host_group),
        "cvm_group": str(cvm_group),
        "qemu_pid": int(qemu_pid),
        "host_tids": host_tids,
        "vcpu_tids": vcpu_tids,
        "host_mba_percent": int(args.resctrl_host_mba) if int(args.resctrl_host_mba) > 0 else None,
    }
    write_json(vm_dir / "resctrl_assignment.json", rec)
    return rec


def cleanup_resctrl(args: argparse.Namespace) -> None:
    if not bool(args.resctrl_enable):
        return
    rc.cleanup_groups(str(args.resctrl_prefix or "ch6perf"))


def main() -> None:
    args = parse_args()
    require_root("[!] run_ch6_aes_perf.py requires root.")

    outdir = Path(args.outdir).resolve() if args.outdir else timestamped_outdir_ch5("ch6_aes_perf")
    outdir.mkdir(parents=True, exist_ok=True)
    print_banner("Chapter 6 Pure AES Benchmark", outdir)
    ensure_artifacts(args.skip_build, outdir / "build_stage")
    collect_host_facts(outdir)

    vm_dir = outdir / "vm"
    proc = launch_vm(args, vm_dir)
    print(f"[run] VM launched (pid={proc.pid}), waiting for guest AES benchmark output ...")
    try:
        if bool(args.resctrl_enable):
            rec = apply_resctrl_partition(args, vm_dir, proc.pid)
            print(
                "[run] resctrl enabled: "
                f"host_mask={rec['host_mask_hex']} cvm_mask={rec['cvm_mask_hex']} "
                f"host_mba={rec.get('host_mba_percent')}"
            )

        perf = wait_perf_output(vm_dir / "qemu_console.log", args.vm_ready_timeout_s)
        if not perf:
            raise SystemExit(f"[run] timeout waiting for AES perf output; see {vm_dir / 'qemu_console.log'}")

        result = {
            "blocks": int(perf.get("blocks", "0")),
            "metric_kind": perf.get("metric_kind", ""),
            "total_cycles": int(perf.get("total_cycles", "0")),
            "total_ns": int(perf.get("total_ns", "0")),
            "cycles_per_call": float(perf.get("cycles_per_call", "0")),
            "ns_per_call": float(perf.get("ns_per_call", "0")),
            "throughput_ops_per_s": float(perf.get("throughput_ops_per_s", "0")),
            "resctrl_enabled": int(bool(args.resctrl_enable)),
            "host_mba_percent": int(args.resctrl_host_mba) if int(args.resctrl_host_mba) > 0 else None,
            "qemu_cpu": int(args.qemu_cpu),
        }
        write_json(outdir / "aes_perf_analysis.json", result)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        chown_to_sudo_user(outdir)
    finally:
        cleanup_resctrl(args)
        stop_proc(proc)


if __name__ == "__main__":
    main()
