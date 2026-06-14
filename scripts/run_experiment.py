#!/usr/bin/env python3
"""
run_experiment.py — 完整 RRFS 实验编排脚本
用于在 AMDSEV 机器上运行 SEV-SNP guest 的 ciphertext cacheable 探针实验

用法:
    python3 scripts/run_experiment.py [选项]

    --smoke              快速冒烟测试：victim_lines=0-7, reps=8
    --victim-lines N-M   指定 victim lines 范围（默认 0-63）
    --reps N             每条 host line 重复次数（默认 32）
    --qemu-cpu N         QEMU vCPU pinned CPU 号（默认 32）
    --host-cpu N         host runner pinned CPU 号（默认 33）
    --no-pin-qemu        不对 QEMU 绑核
    --mem MEM            VM 内存（默认 4G）
    --smp N              虚拟 CPU 数（默认 1）
    --threshold T        慢阈值 cycles（默认 400）
    --outdir DIR         输出目录（默认按时间戳自动创建）
    --skip-other-page    跳过 other_page 测量
    --host-target-page   sync_all 时 host 探测页：primary|secondary|follow_kind
    --gpa-hpa-check      运行 GPA->HPA 正确性小实验（guest 交替写两种值，host 观察密文切换）
    --toggle-line N      小实验 victim line（默认 0）
    --toggle-iters N     小实验切换次数（默认 12）
    --toggle-delay-us N  小实验每次切换间隔 µs（默认 100000）
    --toggle-flush M     小实验 flush 模式：none|line|page（默认 line）
    --skip-build         跳过构建，直接使用现有 build 工件
    --dry-run            只打印命令，不执行
"""

import argparse
import csv
import datetime as dt
import os
import re
import shutil
import statistics
import subprocess
import sys
import time
from pathlib import Path


def env_path(name: str, default: Path) -> Path:
    raw = os.environ.get(name)
    return Path(raw) if raw else default


def default_amdsev_dir() -> Path:
    p1 = Path("<COHERE_REPO>/AMDSEV")
    if p1.exists():
        return p1
    return Path("<AMDSEV_DIR>")


# ──────────────────── 路径常量 ─────────────────────
ROOT        = Path(__file__).resolve().parents[1]          # src/
BUILD       = ROOT / "build"
GUEST_PROBE = BUILD / "guest_probe"
INITRAMFS   = BUILD / "initrd.img"
DEBUGCON    = BUILD / "debugcon.log"
HPA_READER_KO = BUILD / "hpa_reader_kmod.ko"

GUEST_KERNEL = env_path(
    "GUEST_KERNEL",
    next(iter(sorted(Path("/boot").glob("vmlinuz-*snp-guest*"))), Path("")),
)

AMDSEV       = env_path("AMDSEV_DIR", default_amdsev_dir())
QEMU_BIN     = env_path("QEMU_BIN", AMDSEV / "qemu" / "build" / "qemu-system-x86_64")
OVMF_FD      = env_path("OVMF_FD", AMDSEV / "ovmf" / "Build" / "OvmfX64" / "DEBUG_GCC5" / "FV" / "OVMF.fd")
RESULT_ROOT  = env_path("RESULT_ROOT", ROOT.parent / "result")

# regex 解析 guest 打印的 GPA 头
GPA_RE = re.compile(
    r"SNP_PROBE\s+GPA=(0x[0-9a-fA-F]+)\s+PAGE_GPA=(0x[0-9a-fA-F]+)"
    r"\s+OTHER_PAGE_GPA=(0x[0-9a-fA-F]+)"
)


def parse_lines(spec: str) -> list[int]:
    out = []
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            out.extend(range(int(lo), int(hi) + 1))
        elif part:
            out.append(int(part))
    return out


def format_line_mask(lines: list[int]) -> str:
    mask = 0
    for line in lines:
        if not 0 <= line < 64:
            raise ValueError(f"victim line out of range: {line}")
        mask |= 1 << line
    return hex(mask)


def run(cmd, *, check=True, stdout_path=None, input_str=None):
    """运行子进程，支持输出重定向到文件。"""
    if stdout_path:
        with open(stdout_path, "w") as fp:
            return subprocess.run(cmd, stdout=fp, stderr=subprocess.STDOUT,
                                  check=check, text=True, input=input_str)
    return subprocess.run(cmd, check=check, capture_output=True, text=True,
                          input=input_str)


def make_affinity_preexec(cpus: list[int], enabled: bool):
    if not enabled:
        return None
    allowed = sorted({int(c) for c in cpus if int(c) >= 0})
    if not allowed:
        return None

    def _set_affinity():
        os.sched_setaffinity(0, set(allowed))

    return _set_affinity


def stop_proc(proc: subprocess.Popen, timeout_s: float = 5.0):
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def build_artifacts(outdir: Path, dry_run: bool):
    """编译 host_runner 和 guest_probe，构建 initramfs。"""
    build_log = outdir / "build.log"
    print(f"[build] {build_log}")
    if dry_run:
        return

    # make all
    r = run(["make", "-C", str(ROOT), "all"], stdout_path=build_log, check=False)
    if r.returncode != 0:
        sys.exit(f"[build] make all failed, see {build_log}")

    # build initramfs
    if not GUEST_KERNEL:
        sys.exit("[build] SNP guest kernel not found in /boot")

    r = run(
        [str(ROOT / "tools" / "build_initramfs.sh"),
         "--guest-probe", str(GUEST_PROBE),
         "--guest-kmod", str(BUILD / "snp_sync_kmod.ko"),
         "--out", str(INITRAMFS),
         "--kernel", str(GUEST_KERNEL)],
        stdout_path=build_log,
        check=False,
    )
    if r.returncode != 0:
        sys.exit(f"[build] tools/build_initramfs.sh failed, see {build_log}")
    print(f"[build] initramfs: {INITRAMFS}")


def ensure_runtime_paths():
    missing = []
    if not GUEST_KERNEL or not GUEST_KERNEL.exists():
        missing.append(
            "GUEST_KERNEL is missing; set GUEST_KERNEL=/boot/vmlinuz-<snp-guest-kernel>"
        )
    if not QEMU_BIN.exists():
        missing.append(
            f"QEMU_BIN not found at {QEMU_BIN}; set QEMU_BIN or AMDSEV_DIR"
        )
    if not OVMF_FD.exists():
        missing.append(
            f"OVMF_FD not found at {OVMF_FD}; set OVMF_FD or AMDSEV_DIR"
        )
    if missing:
        msg = "\n".join(f"- {item}" for item in missing)
        sys.exit(f"[env] runtime dependency check failed:\n{msg}")


def ensure_toggle_hpa_reader(outdir: Path, dry_run: bool):
    """为 toggle 小实验加载旧成功路径风格的 HPA reader 内核模块。"""
    log_path = outdir / "hpa_reader_module.log"
    print(f"[build] {log_path}")
    if dry_run:
        return
    if os.geteuid() != 0:
        sys.exit("[toggle] hpa_reader_kmod 需要 root 权限加载，请用 sudo 运行")
    if not HPA_READER_KO.exists():
        sys.exit(f"[toggle] missing kernel module: {HPA_READER_KO}")

    run(["rmmod", "hpa_reader_kmod"], check=False, stdout_path=log_path)
    r = run(["insmod", str(HPA_READER_KO)], stdout_path=log_path, check=False)
    if r.returncode != 0:
        sys.exit(f"[toggle] insmod hpa_reader_kmod failed, see {log_path}")


def launch_qemu(victim_line: int, qemu_cpu: str,
                mem: str, smp: str, run_dir: Path, dry_run: bool):
    """
    启动 QEMU SNP VM：
      - 使用 -kernel / -initrd（无需磁盘镜像）
      - debugcon 输出到 DEBUGCON 文件
      - ttyS0 console 输出到 run_dir/qemu_console.log
    """
    DEBUGCON.parent.mkdir(parents=True, exist_ok=True)
    if DEBUGCON.exists():
        DEBUGCON.unlink()

    append = (
        f"console=ttyS0 rdinit=/init panic=-1 quiet "
        f"probe_mode=sync probe_dec_line={victim_line}"
    )

    # EPYC 7763 (Zen3): cbitpos=51, 48 物理地址位
    cbitpos = 51

def measure_pc(run_dir: Path, reps: int, qemu_cpu: int, host_cpu: int,
               outdir: Path, dry_run: bool,
               pin_qemu: bool, mem: str, smp: str,
               no_snp: bool = False,
               llc_sz: int = 32 * 1024 * 1024,
               pc_ways: int = 16,
               pc_line: int = 37,
               pc_probe_cpu: int | None = None):
    """
    LLC Prime+Count 实验（实验 4.4-A）。
    guest 以固定奇偶序列交替访问 target / other_page，
    host 侧做 prime+count，输出 raw_h1_counts.csv / raw_h0_counts.csv。
    """
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / ".hr_preload.lock").unlink(missing_ok=True)
    DEBUGCON = run_dir / "debugcon.log"
    run_dir.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env["HR_MODE"]      = "pc"
    env["HR_OUTDIR"]    = str(outdir)
    env["HR_REPS"]      = str(reps)
    env["HR_CPU"]       = str(host_cpu)
    if pc_probe_cpu is None:
        pc_probe_cpu = host_cpu + 1
    env["HR_PROBE_CPU"] = str(pc_probe_cpu)
    env["HR_SYNC_LOG"]  = str(DEBUGCON)
    env["HR_PC_LLC_SZ"] = str(llc_sz)
    env["HR_PC_WAYS"]   = str(pc_ways)
    env["LD_PRELOAD"]   = "<COHERE_REPO>/src/build/libhost_runner.so"

    # guest 用 pc 模式；默认 victim line 选用 4.2-A+ 中较强的 line 37。
    append = (
        f"console=ttyS0 rdinit=/init panic=-1 quiet "
        f"probe_mode=pc probe_dec_line={pc_line}"
    )

    if no_snp:
        qemu_cmd = [
            str(QEMU_BIN),
            "-enable-kvm", "-cpu", "host",
            "-machine", f"q35,smm=off,memory-backend=ram1",
            "-smp", str(smp), "-m", str(mem), "-no-reboot",
            "-object", f"memory-backend-memfd,id=ram1,size={mem},share=true,prealloc=false",
            "-bios", str(OVMF_FD),
            "-kernel", str(GUEST_KERNEL),
            "-initrd", str(INITRAMFS),
            "-append", append,
            "-serial", f"file:{run_dir}/qemu_console.log",
            "-debugcon", f"file:{DEBUGCON}",
            "-nographic",
            "-monitor", f"unix:{run_dir}/qemu.monitor,server,nowait",
        ]
    else:
        qemu_cmd = [
            str(QEMU_BIN),
            "-enable-kvm", "-cpu", "EPYC-v4",
            "-machine", "q35,smm=off",
            "-machine", "confidential-guest-support=sev0,vmport=off",
            "-machine", "memory-backend=ram1",
            "-smp", str(smp), "-m", str(mem), "-no-reboot",
            "-object", f"memory-backend-memfd,id=ram1,size={mem},share=true,prealloc=false",
            "-object", "sev-snp-guest,id=sev0,policy=0x30000,cbitpos=51,reduced-phys-bits=1",
            "-bios", str(OVMF_FD),
            "-kernel", str(GUEST_KERNEL),
            "-initrd", str(INITRAMFS),
            "-append", append,
            "-serial", f"file:{run_dir}/qemu_console.log",
            "-debugcon", f"file:{DEBUGCON}",
            "-nographic",
            "-monitor", f"unix:{run_dir}/qemu.monitor,server,nowait",
        ]

    preexec_fn = make_affinity_preexec([qemu_cpu, host_cpu], pin_qemu)

    if dry_run:
        print("[runner] PC mode QEMU cmd:", " ".join(qemu_cmd))
        return

    print(f"[pc] launching QEMU ({'plain KVM' if no_snp else 'SEV-SNP'}) with HR_MODE=pc ...")
    qlog = open(run_dir / "qemu.log", "w")
    proc = subprocess.Popen(
        qemu_cmd,
        env=env,
        stdout=qlog,
        stderr=qlog,
        stdin=subprocess.DEVNULL,
        preexec_fn=preexec_fn,
    )
    pid = proc.pid

    # 等待 pc_done.txt
    done_file = outdir / "pc_done.txt"
    timeout = 3600
    elapsed = 0
    while not done_file.exists() and elapsed < timeout:
        time.sleep(5)
        elapsed += 5
        if proc.poll() is not None:
            print(f"[pc] QEMU exited early (rc={proc.returncode})")
            break

    try:
        proc.terminate()
        proc.wait(timeout=10)
    except Exception:
        proc.kill()
    qlog.close()
    print(f"[pc] done. outdir={outdir}")

def measure_all(run_dir: Path, reps: int, qemu_cpu: int, host_cpu: int, threshold: int,
                outdir: Path, dry_run: bool,
                victim_lines: list[int], skip_other_page: bool,
                pin_qemu: bool, mem: str, smp: str,
                host_target_page: str, no_snp: bool = False):
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / ".hr_preload.lock").unlink(missing_ok=True)
    DEBUGCON = run_dir / "debugcon.log"
    SYNCLOG = run_dir / "qemu_console.log"
    run_dir.mkdir(parents=True, exist_ok=True)
    # Pre-create both logs before QEMU start.
    SYNCLOG.write_text("")
    DEBUGCON.write_text("")

    qemu_env = os.environ.copy()
    host_lines_per_victim = int(os.environ.get("HR_HOST_LINES_PER_VICTIM", "64"))
    if host_lines_per_victim <= 0:
        host_lines_per_victim = 64

    line_mask = format_line_mask(victim_lines)

    append = (
        f"console=ttyS0 rdinit=/init panic=-1 quiet "
        f"probe_mode=sync_all "
        f"probe_phase_active_reps={reps} "
        f"probe_host_lines={host_lines_per_victim} "
        f"probe_line_mask={line_mask} probe_measure_other={0 if skip_other_page else 1} "
        f"probe_host_target_page={host_target_page}"
    )

    if no_snp:
        # 普通 KVM 模式：移除 SEV-SNP 专用对象，使用 host CPU 类型
        # 保留 memory-backend-memfd(share=true) 确保 host runner 与 guest
        # 共享同一物理页，跨域缓存驱逐侧信道才能正常观测
        qemu_cmd = [
             str(QEMU_BIN),
            "-enable-kvm", "-cpu", "host",
            "-machine", f"q35,smm=off,memory-backend=ram1",
            "-smp", str(smp), "-m", str(mem), "-no-reboot",
            "-object", f"memory-backend-memfd,id=ram1,size={mem},share=true,prealloc=false",
            "-bios", str(OVMF_FD),
            "-kernel", str(GUEST_KERNEL),
            "-initrd", str(INITRAMFS),
            "-append", append,
            "-serial", f"file:{run_dir}/qemu_console.log",
            "-debugcon", f"file:{DEBUGCON}",
            "-nographic",
            "-monitor", f"unix:{run_dir}/qemu.monitor,server,nowait",
        ]
    else:
        qemu_cmd = [
             str(QEMU_BIN),
            "-enable-kvm", "-cpu", "EPYC-v4",
            "-machine", "q35,smm=off",
            "-machine", "confidential-guest-support=sev0,vmport=off",
            "-machine", "memory-backend=ram1",
            "-smp", str(smp), "-m", str(mem), "-no-reboot",
            "-object", f"memory-backend-memfd,id=ram1,size={mem},share=true,prealloc=false",
            "-object", f"sev-snp-guest,id=sev0,policy=0x30000,cbitpos=51,reduced-phys-bits=1",
            "-bios", str(OVMF_FD),
            "-kernel", str(GUEST_KERNEL),
            "-initrd", str(INITRAMFS),
            "-append", append,
            "-serial", f"file:{run_dir}/qemu_console.log",
            "-debugcon", f"file:{DEBUGCON}",
            "-nographic",
            "-monitor", f"unix:{run_dir}/qemu.monitor,server,nowait",
        ]
    preexec_fn = make_affinity_preexec([qemu_cpu, host_cpu], pin_qemu)

    if dry_run:
        print("[runner]", "QEMU + libhost_runner.so preload (ALL MODE)")
        print("[runner] qemu_cmd:", " ".join(qemu_cmd))
        return

    qlog = open(run_dir / "qemu.log", "w")
    hlog = open(run_dir / "host_runner.log", "w")
    preload_env = qemu_env.copy()
    preload_env.update({
        "HR_MODE": "all",
        "HR_OUTDIR": str(outdir),
        "HR_REPS": str(reps),
        "HR_CPU": str(host_cpu),
        "HR_THRESHOLD": str(threshold),
        # shared_gpa bootstrap is emitted on debugcon; all subsequent metadata
        # now comes from the shared mailbox.
        "HR_SYNC_LOG": str(DEBUGCON),
        "LD_PRELOAD": str(BUILD / "libhost_runner.so"),
    })
    (outdir / ".hr_preload.lock").unlink(missing_ok=True)
    hlog.write("preload_mode=all\n")
    hlog.flush()
    proc = subprocess.Popen(
        qemu_cmd,
        env=preload_env,
        stdin=subprocess.DEVNULL,
        stdout=qlog,
        stderr=subprocess.STDOUT,
        preexec_fn=preexec_fn,
    )

    done_file = outdir / "all_done.txt"
    kind_count = 1 if skip_other_page else 2
    total_syncs = len(victim_lines) * kind_count * host_lines_per_victim * reps
    timeout_s = max(1800, int(total_syncs / 4000) + 600)
    print(f"[runner] waiting for all-mode completion: total_syncs={total_syncs} timeout={timeout_s}s")
    st = time.time()
    last_progress_report = 0.0
    while time.time() - st < timeout_s:
        if done_file.exists():
            print("[runner] ALL DONE correctly intercepted!")
            break
        elapsed = time.time() - st
        if elapsed - last_progress_report >= 15.0:
            progress = summarize_all_mode_progress(
                outdir,
                victim_lines,
                skip_other_page,
                host_lines_per_victim,
            )
            print(f"[runner] progress: elapsed={int(elapsed)}s/{timeout_s}s {progress}")
            last_progress_report = elapsed
        time.sleep(2)
        if proc.poll() is not None:
            print(f"[!] QEMU died early.")
            break

    stop_proc(proc)
    hlog.close()
    qlog.close()


def run_gpa_hpa_check(run_dir: Path, line: int, toggle_iters: int, toggle_delay_us: int,
                      toggle_flush: str, qemu_cpu: int, host_cpu: int,
                      outdir: Path, dry_run: bool,
                      pin_qemu: bool, mem: str, smp: str):
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / ".hr_preload.lock").unlink(missing_ok=True)
    ensure_toggle_hpa_reader(outdir, dry_run)

    debugcon = run_dir / "debugcon.log"
    run_dir.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env["HR_MODE"] = "toggle"
    env["HR_OUTDIR"] = str(outdir)
    env["HR_CPU"] = str(host_cpu)
    env["HR_SYNC_LOG"] = str(debugcon)
    env["HR_TOGGLE_TIMEOUT_S"] = "60"
    env["HR_TOGGLE_READER"] = "module"
    env["LD_PRELOAD"] = "<COHERE_REPO>/src/build/libhost_runner.so"

    append = (
        f"console=ttyS0 rdinit=/init panic=-1 quiet "
        f"probe_mode=cipher_toggle probe_dec_line={line} "
        f"probe_toggle_iters={toggle_iters} probe_toggle_delay_us={toggle_delay_us} "
        f"probe_toggle_flush={toggle_flush}"
    )

    qemu_cmd = [
        str(QEMU_BIN),
        "-enable-kvm", "-cpu", "EPYC-v4",
        "-machine", "q35,smm=off",
        "-machine", "memory-encryption=sev0,vmport=off",
        "-smp", str(smp), "-m", str(mem), "-no-reboot",
        "-object", "sev-snp-guest,id=sev0,policy=0x30000,cbitpos=51,reduced-phys-bits=1",
        "-bios", str(OVMF_FD),
        "-kernel", str(GUEST_KERNEL),
        "-initrd", str(INITRAMFS),
        "-append", append,
        "-serial", f"file:{run_dir}/qemu_console.log",
        "-debugcon", f"file:{debugcon}",
        "-nographic",
        "-monitor", f"unix:{run_dir}/qemu.monitor,server,nowait",
    ]
    preexec_fn = make_affinity_preexec([qemu_cpu, host_cpu], pin_qemu)

    if dry_run:
        print("[runner]", "QEMU + libhost_runner.so (TOGGLE MODE)")
        print("[runner] qemu_cmd:", " ".join(qemu_cmd))
        return

    qlog = open(run_dir / "qemu.log", "w")
    proc = subprocess.Popen(
        qemu_cmd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=qlog,
        stderr=subprocess.STDOUT,
        preexec_fn=preexec_fn,
    )

    done_file = outdir / "toggle_done.txt"
    st = time.time()
    while time.time() - st < 180:
        if done_file.exists():
            print("[runner] toggle check finished")
            break
        time.sleep(1)
        if proc.poll() is not None:
            print("[!] QEMU died early.")
            break

    stop_proc(proc)
    qlog.close()


def summarize_toggle_results(outdir: Path) -> dict[str, str | int]:
    summary = outdir / "toggle_summary.txt"
    result: dict[str, str | int] = {}
    if not summary.exists():
        return result
    for raw in summary.read_text().splitlines():
        if "=" not in raw:
            continue
        k, v = raw.split("=", 1)
        result[k] = v
    return result


def read_row_csv(path: Path) -> list[float]:
    rows = sorted(csv.DictReader(path.open()), key=lambda r: int(r["host_line"]))
    return [float(r["mean_cycles"]) for r in rows]


def write_matrix_csv(path: Path, labels, matrix, col_base: int = 0):
    n_cols = len(matrix[0]) if matrix else 0
    with path.open("w", newline="") as fp:
        wr = csv.writer(fp)
        wr.writerow(["victim_line", *range(col_base, col_base + n_cols)])
        for vl, row in zip(labels, matrix):
            wr.writerow([vl, *[f"{x:.6f}" for x in row]])


def count_completed_rows(path: Path) -> int:
    if not path.exists():
        return 0
    with path.open() as fp:
        row_count = sum(1 for _ in fp)
    return max(0, row_count - 1)


def summarize_all_mode_progress(
    outdir: Path,
    victim_lines: list[int],
    skip_other_page: bool,
    host_lines_per_victim: int,
) -> str:
    phases: list[tuple[int, str]] = []
    for vl in victim_lines:
        phases.append((vl, "same_page"))
        if not skip_other_page:
            phases.append((vl, "other_page"))

    expected_rows_per_phase = max(1, int(host_lines_per_victim))
    rows_total = len(phases) * expected_rows_per_phase
    rows_done_total = 0
    completed = 0
    active_desc = "waiting for first phase"
    for vl, page_name in phases:
        phase_dir = outdir / f"victim_line_{vl:02d}" / page_name
        csv_path = phase_dir / "line_matrix_row.csv"
        meta_path = phase_dir / "meta.txt"

        rows_done = min(expected_rows_per_phase, count_completed_rows(csv_path))
        rows_done_total += rows_done

        # Treat a phase as complete once we have all expected rows even if
        # meta.txt is delayed; this makes progress reporting much less jumpy.
        if meta_path.exists() or rows_done >= expected_rows_per_phase:
            completed += 1
            continue

        if rows_done > 0 or phase_dir.exists():
            active_desc = (
                f"victim_line_{vl:02d}/{page_name} "
                f"rows={rows_done}/{expected_rows_per_phase}"
            )
        else:
            active_desc = f"pending victim_line_{vl:02d}/{page_name}"
        break
    else:
        active_desc = "all phases completed"

    progress_pct = (100.0 * rows_done_total / rows_total) if rows_total else 100.0
    return (
        f"phases={completed}/{len(phases)} "
        f"rows={rows_done_total}/{rows_total} ({progress_pct:.1f}%) "
        f"active={active_desc}"
    )


def write_heatmap(path: Path, matrix, title: str):
    rows = len(matrix)
    cols = len(matrix[0]) if matrix else 0
    if not rows or not cols:
        return ""

    try:
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        print("[!] matplotlib or numpy not installed.")
        return ""

    data = np.array(matrix)

    plt.figure(figsize=(10, 8))

    # 限制极值，避免少量的高延迟或者异常点影响整体配色
    vmin = np.percentile(data, 1)
    vmax = np.percentile(data, 99)
    if vmax <= vmin:
        vmax = vmin + 1.0

    plt.imshow(data, cmap='viridis', aspect='auto', interpolation='nearest', origin='lower', vmin=vmin, vmax=vmax)
    plt.colorbar(label='TSC cycles')

    plt.title(title)
    plt.xlabel('Host Line (Accessed)')
    plt.ylabel('Victim Line (Measured)')

    plt.tight_layout()
    plt.savefig(path, dpi=300)
    plt.close()

    return str(path)


def partition_stats(labels, matrix):
    exp, unexp = [], []
    for vl, row in zip(labels, matrix):
        for hl, val in enumerate(row):
            if (vl < 32) == (hl < 32):
                exp.append(val)
            else:
                unexp.append(val)
    return {
        "expected_mean":   statistics.fmean(exp)   if exp   else 0.0,
        "unexpected_mean": statistics.fmean(unexp) if unexp else 0.0,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--smoke",        action="store_true")
    ap.add_argument("--victim-lines", default="0-63")
    ap.add_argument("--reps",         type=int, default=32)
    ap.add_argument("--qemu-cpu",     type=int, default=32)
    ap.add_argument("--host-cpu",     type=int, default=33)
    ap.add_argument("--pin-qemu",     dest="pin_qemu", action="store_true", default=True)
    ap.add_argument("--no-pin-qemu",  dest="pin_qemu", action="store_false")
    ap.add_argument("--mem",          default="4G")
    ap.add_argument("--smp",          default="1")
    ap.add_argument("--threshold",    type=int, default=400)
    ap.add_argument("--outdir",       default="")
    ap.add_argument("--skip-other-page", action="store_true")
    ap.add_argument("--host-target-page", choices=["primary", "secondary", "follow_kind"], default="primary")
    ap.add_argument("--gpa-hpa-check", action="store_true")
    ap.add_argument("--toggle-line",  type=int, default=0)
    ap.add_argument("--toggle-iters", type=int, default=12)
    ap.add_argument("--toggle-delay-us", type=int, default=100000)
    ap.add_argument("--toggle-flush", choices=["none", "line", "page"], default="line")
    ap.add_argument("--skip-build",   action="store_true")
    ap.add_argument("--no-snp",       action="store_true",
                    help="普通 KVM 模式（移除 SEV-SNP 对象），用于对照实验")
    ap.add_argument("--pc-mode",      action="store_true",
                    help="LLC Prime+Count 模式（HR_MODE=pc），用于实验 4.4-A")
    ap.add_argument("--pc-llc-sz",    type=int, default=32 * 1024 * 1024,
                    help="LLC 大小（字节），默认 32 MiB（单 CCD）")
    ap.add_argument("--pc-ways",      type=int, default=16,
                    help="LLC eviction set 路数，默认 16")
    ap.add_argument("--pc-line",      type=int, default=37,
                    help="PC victim line，默认 37（来自 4.2-A+ 的高信号缓存行）")
    ap.add_argument("--pc-probe-cpu", type=int, default=None,
                    help="PC probe 线程 CPU（默认 host-cpu+1）")
    ap.add_argument("--dry-run",      action="store_true")
    args = ap.parse_args()

    if args.smoke:
        args.victim_lines = "0-7"
        args.reps = 8

    ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = (Path(args.outdir).resolve() if args.outdir
              else RESULT_ROOT / f"amd_ciphertext_{ts}")
    outdir.mkdir(parents=True, exist_ok=True)
    print(f"[run] outdir={outdir}")

    # 1. 构建
    if args.skip_build:
        print("[build] skip_build=1, reusing existing artifacts")
    else:
        build_artifacts(outdir, args.dry_run)

    ensure_runtime_paths()


    victim_lines = parse_lines(args.victim_lines)

    if args.gpa_hpa_check:
        print("\n[gpa_hpa_check] toggling guest plaintext and capturing ciphertext on host ...")
        run_gpa_hpa_check(outdir / "vm_toggle", args.toggle_line, args.toggle_iters,
                          args.toggle_delay_us, args.toggle_flush,
                          args.qemu_cpu, args.host_cpu, outdir, args.dry_run,
                          args.pin_qemu, args.mem, args.smp)
        if not args.dry_run:
            info = summarize_toggle_results(outdir)
            summary_lines = [
                "# GPA->HPA toggle validation",
                f"outdir={outdir}",
                f"line={args.toggle_line}",
                f"toggle_iters={args.toggle_iters}",
                f"toggle_delay_us={args.toggle_delay_us}",
                f"toggle_flush={args.toggle_flush}",
            ]
            for key in ["line_gpa", "page_hpa", "events", "transitions", "fingerprint_A", "fingerprint_B", "toggles_ok", "mismatches"]:
                if key in info:
                    summary_lines.append(f"{key}={info[key]}")
            for key in sorted(info.keys()):
                if key.startswith("mode_") or key in {"reader", "hpa_mismatches", "toggles_any_mode"}:
                    summary_lines.append(f"{key}={info[key]}")
            (outdir / "summary.txt").write_text("\n".join(summary_lines) + "\n")
            print(f"[result] toggles_ok={info.get('toggles_ok', 'NA')} mismatches={info.get('mismatches', 'NA')}")
            print(f"[done] {outdir}/summary.txt")
        return

    same_rows: dict[int, list[float]] = {}
    other_rows: dict[int, list[float]] = {}
    host_line_base = int(os.environ.get("HR_HOST_LINE_BASE", "0"))

    if args.pc_mode:
        label = "plain KVM" if args.no_snp else "SEV-SNP"
        print(f"\n[pc_mode] LLC Prime+Count ({label}) ...")
        measure_pc(outdir / "vm_pc", args.reps, args.qemu_cpu, args.host_cpu,
                   outdir, args.dry_run,
                   args.pin_qemu, args.mem, args.smp,
                   no_snp=args.no_snp,
                   llc_sz=args.pc_llc_sz,
                   pc_ways=args.pc_ways,
                   pc_line=args.pc_line,
                   pc_probe_cpu=args.pc_probe_cpu)
        return

    print(f"\n[all_mode] measuring everything in ONE QEMU BOOT ({'plain KVM' if args.no_snp else 'SEV-SNP'}) ...")
    measure_all(outdir / "vm_all", args.reps, args.qemu_cpu, args.host_cpu,
                args.threshold, outdir, args.dry_run,
                victim_lines, args.skip_other_page,
                args.pin_qemu, args.mem, args.smp, args.host_target_page,
                no_snp=args.no_snp)

    if not args.dry_run:
        for vl in victim_lines:
            vl_dir = outdir / f"victim_line_{vl:02d}"

            s_csv = vl_dir / "same_page" / "line_matrix_row.csv"
            if s_csv.exists():
                same_rows[vl] = read_row_csv(s_csv)

            if not args.skip_other_page:
                o_csv = vl_dir / "other_page" / "line_matrix_row.csv"
                if o_csv.exists():
                    other_rows[vl] = read_row_csv(o_csv)

    # 3. 生成矩阵 CSV + SVG heatmap + summary
    labels = sorted(same_rows.keys())
    summary_lines = [
        "# AMD RRFS Ciphertext Heatmap",
        f"outdir={outdir}",
        f"victim_lines={args.victim_lines}",
        f"reps={args.reps}",
        f"mem={args.mem}",
        f"smp={args.smp}",
        f"mode=amd-ciphertext-cacheable",
    ]

    if labels:
        same_matrix = [same_rows[i] for i in labels]
        write_matrix_csv(outdir / "same_page_matrix.csv", labels, same_matrix, col_base=host_line_base)
        heatmap_path = write_heatmap(
            outdir / "same_page_heatmap_tsc.png", same_matrix,
            "AMD Ciphertext Same-Page Heatmap (TSC cycles)"
        )
        summary_lines.append(f"same_page_heatmap={heatmap_path}")
        st = partition_stats(labels, same_matrix)
        summary_lines.append(f"same_page_expected_mean={st['expected_mean']:.3f}")
        summary_lines.append(f"same_page_unexpected_mean={st['unexpected_mean']:.3f}")
        print(f"[result] same-page partition: expected={st['expected_mean']:.1f}  unexpected={st['unexpected_mean']:.1f}")

    if other_rows:
        other_labels = sorted(other_rows.keys())
        other_matrix = [other_rows[i] for i in other_labels]
        write_matrix_csv(outdir / "other_page_matrix.csv", other_labels, other_matrix, col_base=host_line_base)
        heatmap2_path = write_heatmap(
            outdir / "other_page_heatmap_tsc.png", other_matrix,
            "AMD Ciphertext Other-Page Heatmap (TSC cycles)"
        )
        summary_lines.append(f"other_page_heatmap={heatmap2_path}")
        all_other = [x for row in other_matrix for x in row]
        if all_other:
            summary_lines.append(f"other_page_mean={statistics.fmean(all_other):.3f}")

    (outdir / "summary.txt").write_text("\n".join(summary_lines) + "\n")
    print(f"\n[done] {outdir}/summary.txt")


if __name__ == "__main__":
    main()
