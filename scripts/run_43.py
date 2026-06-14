#!/usr/bin/env python3
"""
run_43.py — Chapter 4.3 experiments orchestration (script-only, no auto-run).

Subcommands:
  python3 scripts/run_43.py a   # 4.3-A: idle vs noisy loads
  python3 scripts/run_43.py b   # 4.3-B: pinned+isolated vs unpinned
  python3 scripts/run_43.py d   # 4.3-D: signal granularity degradation
  python3 scripts/run_43.py e   # 4.3-E: interleaving pattern + coherence/contention
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import itertools
import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


SCRIPT_DIR = Path(__file__).resolve().parent
SRC_DIR = SCRIPT_DIR.parent
REPO_ROOT = SRC_DIR.parent
RUN_EXPERIMENT = SCRIPT_DIR / "run_experiment.py"
RESULT_CH4 = REPO_ROOT / "result" / "ch4"
CONTENTION_PAUSE_US = 1

BUILD_DIR = SRC_DIR / "build"
INITRAMFS = BUILD_DIR / "initrd.img"
GUEST_KERNEL = next(iter(sorted(Path("/boot").glob("vmlinuz-*snp-guest*"))), None)
AMDSEV = Path("<AMDSEV_DIR>")
QEMU_BIN = AMDSEV / "qemu" / "build" / "qemu-system-x86_64"
OVMF_FD = AMDSEV / "ovmf" / "Build" / "OvmfX64" / "DEBUG_GCC5" / "FV" / "OVMF.fd"


def now() -> str:
    return dt.datetime.now().isoformat(timespec="seconds")


def dir_stamp() -> str:
    return dt.datetime.now().strftime("%Y%m%d_%H%M%S")


def ensure_tool(name: str, hint: str):
    if shutil.which(name) is None:
        raise SystemExit(f"[missing] {name}: {hint}")


def run_checked(cmd: list[str], *, cwd: Path | None = None, env: dict | None = None):
    print("[cmd]", " ".join(cmd))
    subprocess.run(cmd, cwd=str(cwd) if cwd else None, env=env, check=True)


def stop_proc(proc: subprocess.Popen, timeout_s: float = 5.0):
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def ensure_artifacts(skip_build: bool, outdir: Path):
    outdir.mkdir(parents=True, exist_ok=True)
    if skip_build:
        print("[build] skip_build=1")
        return
    log = outdir / "build.log"
    with log.open("w") as fp:
        print("[build] make all && make initramfs")
        subprocess.run(["make", "all"], cwd=str(SRC_DIR), stdout=fp, stderr=subprocess.STDOUT, check=True)
        subprocess.run(["make", "initramfs"], cwd=str(SRC_DIR), stdout=fp, stderr=subprocess.STDOUT, check=True)
    print(f"[build] done: {log}")


def _run_experiment(
    outdir: Path,
    *,
    reps: int,
    qemu_cpu: int,
    host_cpu: int,
    pin_qemu: bool,
    mem: str,
    smp: str,
    victim_lines: str,
    host_target_page: str = "primary",
    env_overrides: dict | None = None,
):
    cmd = [
        "sudo",
        "-E",
        "python3",
        str(RUN_EXPERIMENT),
        "--reps",
        str(reps),
        "--victim-lines",
        victim_lines,
        "--outdir",
        str(outdir),
        "--qemu-cpu",
        str(qemu_cpu),
        "--host-cpu",
        str(host_cpu),
        "--mem",
        str(mem),
        "--smp",
        str(smp),
        "--skip-build",
        "--host-target-page",
        host_target_page,
    ]
    cmd.append("--pin-qemu" if pin_qemu else "--no-pin-qemu")
    env = os.environ.copy()
    if env_overrides:
        env.update(env_overrides)
    run_checked(cmd, cwd=SRC_DIR, env=env)


def run_experiment_42a_style(
    outdir: Path,
    *,
    reps: int,
    qemu_cpu: int,
    host_cpu: int,
    pin_qemu: bool,
    mem: str,
    smp: str,
    victim_line: int,
    host_target_page: str = "primary",
):
    _run_experiment(
        outdir,
        reps=reps,
        qemu_cpu=qemu_cpu,
        host_cpu=host_cpu,
        pin_qemu=pin_qemu,
        mem=mem,
        smp=smp,
        victim_lines=str(victim_line),
        host_target_page=host_target_page,
        env_overrides={
            "HR_RAW_FOCUS_VLINE": str(victim_line),
            "HR_HOST_LINES_PER_VICTIM": "1",
            "HR_HOST_LINE_BASE": str(victim_line),
        },
    )


def run_experiment_full_matrix(
    outdir: Path,
    *,
    reps: int,
    qemu_cpu: int,
    host_cpu: int,
    pin_qemu: bool,
    mem: str,
    smp: str,
    victim_lines: str = "0-63",
    host_target_page: str = "primary",
):
    _run_experiment(
        outdir,
        reps=reps,
        qemu_cpu=qemu_cpu,
        host_cpu=host_cpu,
        pin_qemu=pin_qemu,
        mem=mem,
        smp=smp,
        victim_lines=victim_lines,
        host_target_page=host_target_page,
    )


@dataclass
class BgProc:
    name: str
    cmd: list[str]
    proc: subprocess.Popen
    log_path: Path
    pgid: int | None = None


def spawn_bg(name: str, cmd: list[str], log_path: Path, env: dict | None = None) -> BgProc:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    fp = log_path.open("w")
    proc = subprocess.Popen(
        cmd,
        cwd=str(SRC_DIR),
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=fp,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )
    return BgProc(name=name, cmd=cmd, proc=proc, log_path=log_path, pgid=proc.pid)


def write_meta(path: Path, lines: list[str]):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n")


def noise_qemu_cmd(mode: str, run_dir: Path, cpu: int, mem: str = "1G") -> list[str]:
    if GUEST_KERNEL is None:
        raise SystemExit("[noise-vm] SNP guest kernel not found in /boot")
    base_cmd = [
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
        mem,
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
        f"console=ttyS0 rdinit=/init panic=-1 quiet probe_mode={mode} probe_dec_line=0",
        "-serial",
        f"file:{run_dir}/qemu_console.log",
        "-debugcon",
        f"file:{run_dir}/debugcon.log",
        "-nographic",
        "-monitor",
        f"unix:{run_dir}/qemu.monitor,server,nowait",
    ]
    if cpu >= 0:
        return ["sudo", "-E", "taskset", "-c", str(cpu), *base_cmd]
    return ["sudo", "-E", *base_cmd]


def launch_noise_vms(outdir: Path, count: int, base_cpu: int) -> list[BgProc]:
    procs: list[BgProc] = []
    modes = ["hammer64", "contention"]
    for i in range(count):
        vm_dir = outdir / f"noise_vm_{i+1}"
        mode = modes[i % len(modes)]
        cpu = base_cpu + i if base_cpu >= 0 else -1
        cmd = noise_qemu_cmd(mode, vm_dir, cpu)
        bp = spawn_bg(f"noise_vm_{i+1}", cmd, vm_dir / "qemu.log")
        procs.append(bp)
    return procs


def stop_bg_all(procs: Iterable[BgProc]):
    for bp in procs:
        if bp.pgid is not None:
            try:
                os.killpg(bp.pgid, 15)
            except ProcessLookupError:
                pass
        stop_proc(bp.proc)
        if bp.pgid is not None:
            try:
                os.killpg(bp.pgid, 9)
            except ProcessLookupError:
                pass


def load_matrix_csv(path: Path) -> list[list[float]]:
    rows: list[list[float]] = []
    with path.open(newline="") as fp:
        reader = csv.reader(fp)
        next(reader, None)  # header
        for row in reader:
            if not row:
                continue
            vals = [float(x) for x in row[1:]]
            rows.append(vals)
    return rows


def load_labeled_matrix_csv(path: Path) -> tuple[list[int], list[list[float]]]:
    labels: list[int] = []
    rows: list[list[float]] = []
    with path.open(newline="") as fp:
        reader = csv.reader(fp)
        next(reader, None)  # header
        for row in reader:
            if not row:
                continue
            labels.append(int(float(row[0])))
            rows.append([float(x) for x in row[1:]])
    return labels, rows


def aggregate_groups(row: list[float], groups: list[list[int]]) -> list[float]:
    out: list[float] = []
    for group in groups:
        if not group:
            out.append(0.0)
            continue
        out.append(sum(row[idx] for idx in group) / len(group))
    return out


def _l2_normalize(vec: list[float]) -> list[float]:
    norm2 = sum(x * x for x in vec)
    if norm2 <= 1e-18:
        return [0.0 for _ in vec]
    inv = 1.0 / (norm2 ** 0.5)
    return [x * inv for x in vec]


def _cosine(a: list[float], b: list[float]) -> float:
    return sum(x * y for x, y in zip(a, b))


def _kmeans_cosine(vectors: list[list[float]], k: int, max_iter: int = 64) -> list[int]:
    if not vectors:
        raise ValueError("vectors must not be empty")
    if k <= 0 or k > len(vectors):
        raise ValueError(f"invalid k={k} for n={len(vectors)}")

    normed = [_l2_normalize(v) for v in vectors]
    dim = len(normed[0])

    # Deterministic farthest-point init.
    seed_ids = [0]
    while len(seed_ids) < k:
        best_idx = -1
        best_dist = -1.0
        for i, v in enumerate(normed):
            if i in seed_ids:
                continue
            nearest_sim = max(_cosine(v, normed[s]) for s in seed_ids)
            dist = 1.0 - nearest_sim
            if dist > best_dist:
                best_dist = dist
                best_idx = i
        seed_ids.append(best_idx)
    centers = [normed[s][:] for s in seed_ids]

    labels = [-1 for _ in normed]
    for _ in range(max_iter):
        changed = False
        for i, v in enumerate(normed):
            best_c = max(range(k), key=lambda c: _cosine(v, centers[c]))
            if labels[i] != best_c:
                labels[i] = best_c
                changed = True

        for c in range(k):
            if any(lbl == c for lbl in labels):
                continue
            # Repair empty cluster with the least-confident sample.
            donor = max(
                range(len(normed)),
                key=lambda i: 1.0 - _cosine(normed[i], centers[labels[i]]),
            )
            labels[donor] = c
            changed = True

        new_centers: list[list[float]] = []
        for c in range(k):
            members = [normed[i] for i, lbl in enumerate(labels) if lbl == c]
            accum = [0.0] * dim
            for m in members:
                for j, x in enumerate(m):
                    accum[j] += x
            inv = 1.0 / len(members)
            new_centers.append(_l2_normalize([x * inv for x in accum]))
        centers = new_centers
        if not changed:
            break

    return labels


def _labels_to_groups(labels: list[int], k: int) -> list[list[int]]:
    groups = [[] for _ in range(k)]
    for i, lbl in enumerate(labels):
        groups[lbl].append(i)
    for g in groups:
        g.sort()
    return groups


def build_contiguous_partition(unit_size: int) -> tuple[list[list[int]], dict[int, int]]:
    groups = [list(range(i, i + unit_size)) for i in range(0, 64, unit_size)]
    victim_group_by_line = {line: (line // unit_size) for line in range(64)}
    return groups, victim_group_by_line


def learn_interleaving_partition(
    victim_lines: list[int],
    same_matrix: list[list[float]],
    group_count: int,
) -> tuple[list[list[int]], dict[int, int], dict[str, str]]:
    if len(same_matrix) != len(victim_lines):
        raise ValueError("victim_lines and same_matrix length mismatch")
    if not same_matrix or any(len(row) != 64 for row in same_matrix):
        raise ValueError("same_matrix must be non-empty and 64-wide")

    row_labels = _kmeans_cosine(same_matrix, group_count)
    col_vectors = [[same_matrix[r][c] for r in range(len(same_matrix))] for c in range(64)]
    col_labels = _kmeans_cosine(col_vectors, group_count)

    victim_groups_raw = _labels_to_groups(row_labels, group_count)
    host_groups_raw = _labels_to_groups(col_labels, group_count)

    interaction = [[0.0 for _ in range(group_count)] for _ in range(group_count)]
    for vg in range(group_count):
        rows = victim_groups_raw[vg]
        for hg in range(group_count):
            cols = host_groups_raw[hg]
            if not rows or not cols:
                interaction[vg][hg] = float("-inf")
                continue
            total = 0.0
            count = 0
            for r in rows:
                row = same_matrix[r]
                for c in cols:
                    total += row[c]
                    count += 1
            interaction[vg][hg] = total / count

    best_perm: tuple[int, ...] | None = None
    best_score = float("-inf")
    for perm in itertools.permutations(range(group_count)):
        score = sum(interaction[vg][perm[vg]] for vg in range(group_count))
        if score > best_score:
            best_score = score
            best_perm = perm
    if best_perm is None:
        raise RuntimeError("failed to align learned victim/host groups")

    host_groups = [host_groups_raw[best_perm[vg]] for vg in range(group_count)]
    victim_group_by_line = {
        victim_lines[row_idx]: row_labels[row_idx] for row_idx in range(len(victim_lines))
    }

    def _fmt_groups(prefix: str, groups: list[list[int]]) -> str:
        parts: list[str] = []
        for gi, grp in enumerate(groups):
            parts.append(f"{prefix}{gi}=" + ",".join(str(x) for x in grp))
        return " | ".join(parts)

    victim_groups_by_line = [[] for _ in range(group_count)]
    for vline, g in sorted(victim_group_by_line.items()):
        victim_groups_by_line[g].append(vline)

    meta = {
        "alignment_score": f"{best_score:.6f}",
        "victim_groups": _fmt_groups("v", victim_groups_by_line),
        "host_groups": _fmt_groups("h", host_groups),
    }
    return host_groups, victim_group_by_line, meta


def compute_granularity_metrics(
    victim_lines: list[int],
    same_matrix: list[list[float]],
    other_matrix: list[list[float]],
    *,
    host_groups: list[list[int]],
    victim_group_by_line: dict[int, int],
) -> dict[str, float]:
    h1_scores: list[float] = []
    h0_scores: list[float] = []
    localization_hits = 0

    for victim_line, same_row, other_row in zip(victim_lines, same_matrix, other_matrix):
        h1_units = aggregate_groups(same_row, host_groups)
        h0_units = aggregate_groups(other_row, host_groups)
        h1_scores.append(max(h1_units))
        h0_scores.append(max(h0_units))

        # Localization accuracy: can the strongest learned/defined unit identify the victim unit?
        pred_unit = max(range(len(h1_units)), key=lambda idx: h1_units[idx])
        true_unit = victim_group_by_line.get(victim_line, -1)
        if pred_unit == true_unit:
            localization_hits += 1

    localization_acc = localization_hits / len(same_matrix) if same_matrix else 0.0
    return {
        "unit_size": float(64 / len(host_groups)),
        "h0_mean": sum(h0_scores) / len(h0_scores),
        "h1_mean": sum(h1_scores) / len(h1_scores),
        "delta": (sum(h1_scores) / len(h1_scores)) - (sum(h0_scores) / len(h0_scores)),
        # Localization metric (what 4.3-D mainly cares about)
        "localization_accuracy": localization_acc,
        "samples_per_class": float(len(h0_scores)),
    }


def build_eviction_pattern_single(page_run: Path, out_dir: Path, threshold: float | None):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np

    same = load_matrix_csv(page_run / "same_page_matrix.csv")
    if len(same) != 64 or any(len(row) != 64 for row in same):
        raise SystemExit("[4.3-E] single-page pattern matrix shape mismatch, expected 64x64")
    same_arr = np.array(same, dtype=float)
    if threshold is None:
        threshold = float(np.percentile(same_arr, 95.0))
        threshold_mode = "adaptive_p95"
    else:
        threshold = float(threshold)
        threshold_mode = "manual"
    binary = (same_arr > threshold).astype(int)

    out_dir.mkdir(parents=True, exist_ok=True)
    csv_path = out_dir / "eviction_pattern_binary.csv"
    with csv_path.open("w", newline="") as fp:
        wr = csv.writer(fp)
        wr.writerow(["plain_line", *[f"cipher_{i}" for i in range(64)]])
        for i in range(64):
            wr.writerow([i, *binary[i].tolist()])

    fig, ax = plt.subplots(figsize=(6.8, 6.2))
    cmap = matplotlib.colors.ListedColormap(["white", "black"])
    ax.imshow(binary, cmap=cmap, origin="lower", interpolation="nearest", aspect="equal", vmin=0, vmax=1)
    ax.set_xlabel("Ciphertext Line")
    ax.set_ylabel("Plaintext Line")
    ax.set_title("Eviction Pattern (black=eviction, white=no eviction)")
    fig.tight_layout()
    fig.savefig(out_dir / "eviction_pattern_bw.png", dpi=300)
    plt.close(fig)

    write_meta(
        out_dir / "pattern_meta.txt",
        [
            f"threshold={threshold}",
            f"threshold_mode={threshold_mode}",
            "shape=64x64",
            f"source_run={page_run}",
            "black=eviction",
            "white=no_eviction",
            f"generated_at={now()}",
        ],
    )
    return threshold, threshold_mode


def run_contention_capture(
    outdir: Path,
    *,
    reps: int,
    qemu_cpu: int,
    host_cpu: int,
    pin_qemu: bool,
    mem: str,
    smp: str,
):
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / ".hr_preload.lock").unlink(missing_ok=True)
    debugcon = outdir / "debugcon.log"
    qemu_log = outdir / "qemu.log"
    stale_outputs = [
        debugcon,
        qemu_log,
        outdir / "qemu_console.log",
        outdir / "qemu.monitor",
        outdir / "contention_done.txt",
        outdir / "raw_h0_cycles.csv",
        outdir / "raw_h1_cycles.csv",
        outdir / "meta.txt",
    ]

    for path in stale_outputs:
        try:
            path.unlink()
        except FileNotFoundError:
            pass

    if os.geteuid() != 0:
        raise SystemExit(
            "[4.3-E] contention capture must be run as root. "
            "Nested sudo strips LD_PRELOAD and prevents libhost_runner.so "
            "from attaching to the real QEMU process."
        )

    env = os.environ.copy()
    env["HR_MODE"] = "contention"
    env["HR_REPS"] = str(reps)
    env["HR_CPU"] = str(host_cpu)
    env["HR_OUTDIR"] = str(outdir)
    env["HR_SYNC_LOG"] = str(debugcon)
    env["LD_PRELOAD"] = str(BUILD_DIR / "libhost_runner.so")

    append = (
        "console=ttyS0 rdinit=/init panic=-1 quiet "
        "probe_mode=contention probe_dec_line=0"
    )
    base_qemu_cmd = [
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
        append,
        "-serial",
        f"file:{outdir}/qemu_console.log",
        "-debugcon",
        f"file:{debugcon}",
        "-nographic",
        "-monitor",
        f"unix:{outdir}/qemu.monitor,server,nowait",
    ]
    # Launch QEMU directly once the outer script already runs as root.
    # An extra `sudo -E` drops LD_PRELOAD on this system, which makes the
    # host runner attach to sudo/taskset instead of the real QEMU process.
    preexec_fn = None
    if pin_qemu and qemu_cpu >= 0:
        def _pin_qemu_cpu():
            os.sched_setaffinity(0, {qemu_cpu})
        preexec_fn = _pin_qemu_cpu

    done_file = outdir / "contention_done.txt"
    timeout_s = max(1200, int(reps / 100 + 600))

    with qemu_log.open("w") as fp:
        proc = subprocess.Popen(
            base_qemu_cmd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=fp,
            stderr=subprocess.STDOUT,
            cwd=str(SRC_DIR),
            preexec_fn=preexec_fn,
        )
        st = dt.datetime.now()
        while (dt.datetime.now() - st).total_seconds() < timeout_s:
            if done_file.exists():
                break
            if proc.poll() is not None:
                break
            time.sleep(2)
        stop_proc(proc)

    if not done_file.exists():
        raise SystemExit(f"[4.3-E] contention capture not completed: {outdir}")


def run_43a(args: argparse.Namespace):
    outdir = (
        Path(args.outdir).resolve()
        if args.outdir
        else RESULT_CH4 / f"exp4_3_a_{dir_stamp()}"
    )
    outdir.mkdir(parents=True, exist_ok=True)
    ensure_artifacts(args.skip_build, outdir)

    ensure_tool("stress-ng", "Install stress-ng (e.g., apt install stress-ng)")
    if not QEMU_BIN.exists():
        raise SystemExit(f"[missing] qemu binary: {QEMU_BIN}")
    if not INITRAMFS.exists():
        raise SystemExit(f"[missing] initramfs: {INITRAMFS}")

    conditions = [
        ("idle", "空载", None),
        ("cpu_full", "CPU 满载", ["stress-ng", "--cpu", str(os.cpu_count() or 1), "--cpu-method", "all"]),
        ("mem_bw", "内存带宽压力", ["stress-ng", "--stream", "4", "--stream-ops", "0"]),
        ("multi_vm", "多 VM 并发", None),
    ]

    for name, desc, stress_cmd in conditions:
        cond_dir = outdir / name
        cond_dir.mkdir(parents=True, exist_ok=True)
        bg: list[BgProc] = []
        start_ts = now()
        meta_lines = [
            f"condition={name}",
            f"description={desc}",
            f"start_time={start_ts}",
        ]
        try:
            if stress_cmd is not None:
                cmd = ["sudo", "-E", *stress_cmd]
                bp = spawn_bg(f"load_{name}", cmd, cond_dir / "load.log")
                bg.append(bp)
                meta_lines.append(f"load_cmd={' '.join(cmd)}")
                meta_lines.append(f"load_pid={bp.proc.pid}")
            elif name == "multi_vm":
                bg = launch_noise_vms(cond_dir, args.noise_vms, args.noise_base_cpu)
                for bp in bg:
                    meta_lines.append(f"{bp.name}_cmd={' '.join(bp.cmd)}")
                    meta_lines.append(f"{bp.name}_pid={bp.proc.pid}")

            run_experiment_42a_style(
                cond_dir,
                reps=args.reps,
                qemu_cpu=args.qemu_cpu,
                host_cpu=args.host_cpu,
                pin_qemu=True,
                mem=args.mem,
                smp=args.smp,
                victim_line=args.victim_line,
            )
            meta_lines.append("status=ok")
        finally:
            stop_bg_all(bg)
            meta_lines.append(f"end_time={now()}")
            write_meta(cond_dir / "load_meta.txt", meta_lines)


def systemctl_is_active(service: str) -> str:
    cp = subprocess.run(
        ["systemctl", "is-active", service],
        check=False,
        capture_output=True,
        text=True,
    )
    return cp.stdout.strip() if cp.stdout else cp.stderr.strip()


def run_43b(args: argparse.Namespace):
    outdir = (
        Path(args.outdir).resolve()
        if args.outdir
        else RESULT_CH4 / f"exp4_3_b_{dir_stamp()}"
    )
    outdir.mkdir(parents=True, exist_ok=True)
    ensure_artifacts(args.skip_build, outdir)

    original_state = systemctl_is_active("irqbalance")
    state_log = outdir / "irqbalance_state.log"
    lines = [f"start_time={now()}", f"original_state={original_state}"]

    try:
        run_checked(["sudo", "systemctl", "stop", "irqbalance"])
        lines.append(f"after_stop={systemctl_is_active('irqbalance')}")
        run_experiment_42a_style(
            outdir / "pinned_isolated",
            reps=args.reps,
            qemu_cpu=args.qemu_cpu,
            host_cpu=args.host_cpu,
            pin_qemu=True,
            mem=args.mem,
            smp=args.smp,
            victim_line=args.victim_line,
        )

        run_checked(["sudo", "systemctl", "start", "irqbalance"])
        lines.append(f"after_start={systemctl_is_active('irqbalance')}")
        run_experiment_42a_style(
            outdir / "unpinned",
            reps=args.reps,
            qemu_cpu=args.qemu_cpu,
            host_cpu=-1,
            pin_qemu=False,
            mem=args.mem,
            smp=args.smp,
            victim_line=args.victim_line,
        )
    finally:
        if original_state == "active":
            subprocess.run(["sudo", "systemctl", "start", "irqbalance"], check=False)
        elif original_state in ("inactive", "failed"):
            subprocess.run(["sudo", "systemctl", "stop", "irqbalance"], check=False)
        lines.append(f"restored_state={systemctl_is_active('irqbalance')}")
        lines.append(f"end_time={now()}")
        state_log.write_text("\n".join(lines) + "\n")


def run_43e(args: argparse.Namespace):
    outdir = (
        Path(args.outdir).resolve()
        if args.outdir
        else RESULT_CH4 / f"exp4_3_e_{dir_stamp()}"
    )
    label_dir = outdir / args.interleave_label
    label_dir.mkdir(parents=True, exist_ok=True)
    ensure_artifacts(args.skip_build, label_dir)

    if not QEMU_BIN.exists():
        raise SystemExit(f"[missing] qemu binary: {QEMU_BIN}")
    if not INITRAMFS.exists():
        raise SystemExit(f"[missing] initramfs: {INITRAMFS}")
    if GUEST_KERNEL is None:
        raise SystemExit("[missing] SNP guest kernel not found in /boot")

    # 1) Eviction pattern data:
    #    capture a single 4KB page and build a 64x64 binary pattern from same-page measurements.
    pattern_page = label_dir / "pattern_page"
    run_experiment_full_matrix(
        pattern_page,
        reps=args.pattern_reps,
        qemu_cpu=args.qemu_cpu,
        host_cpu=args.host_cpu,
        pin_qemu=True,
        mem=args.mem,
        smp=args.smp,
        victim_lines="0-63",
        host_target_page="primary",
    )
    actual_threshold, threshold_mode = build_eviction_pattern_single(
        pattern_page, label_dir, args.pattern_threshold
    )

    # 2) Coherence signal (reuse 4.2-A style)
    run_experiment_42a_style(
        label_dir / "coherence",
        reps=args.reps,
        qemu_cpu=args.qemu_cpu,
        host_cpu=args.host_cpu,
        pin_qemu=True,
        mem=args.mem,
        smp=args.smp,
        victim_line=args.victim_line,
        host_target_page="primary",
    )

    # 3) Contention signal (reuse 4.2-B style)
    run_contention_capture(
        label_dir / "contention",
        reps=args.reps,
        qemu_cpu=args.qemu_cpu,
        host_cpu=args.host_cpu,
        pin_qemu=True,
        mem=args.mem,
        smp=args.smp,
    )

    write_meta(
        label_dir / "exp43e_meta.txt",
        [
            f"interleave_label={args.interleave_label}",
            f"pattern_reps={args.pattern_reps}",
            f"signal_reps={args.reps}",
            f"pattern_threshold={actual_threshold}",
            f"pattern_threshold_mode={threshold_mode}",
            f"contention_pause_us={CONTENTION_PAUSE_US}",
            "pattern_shape=64x64",
            f"pattern_source_run={pattern_page}",
            f"completed_at={now()}",
        ],
    )


def run_43d(args: argparse.Namespace):
    outdir = (
        Path(args.outdir).resolve()
        if args.outdir
        else RESULT_CH4 / f"exp4_3_d_{dir_stamp()}"
    )
    outdir.mkdir(parents=True, exist_ok=True)
    ensure_artifacts(args.skip_build, outdir)

    capture_dir = outdir / "capture"
    run_experiment_full_matrix(
        capture_dir,
        reps=args.reps,
        qemu_cpu=args.qemu_cpu,
        host_cpu=args.host_cpu,
        pin_qemu=True,
        mem=args.mem,
        smp=args.smp,
        victim_lines="0-63",
        host_target_page="primary",
    )

    same_path = capture_dir / "same_page_matrix.csv"
    other_path = capture_dir / "other_page_matrix.csv"
    if not same_path.exists() or not other_path.exists():
        raise SystemExit(
            f"[4.3-D] missing matrix files: same={same_path.exists()} other={other_path.exists()}"
        )

    same_labels, same_matrix = load_labeled_matrix_csv(same_path)
    other_labels, other_matrix = load_labeled_matrix_csv(other_path)
    if len(same_matrix) != 64 or len(other_matrix) != 64:
        raise SystemExit("[4.3-D] matrix shape mismatch, expected 64x64 for both same/other")
    if same_labels != other_labels:
        raise SystemExit("[4.3-D] same/other victim_line layout mismatch")

    rows = [
        ("cacheline_64B", 1, "contiguous"),
        ("block_256B", 4, "contiguous"),
        ("partition_1_4_page", 4, "learned_interleaving"),
        ("partition_1_2_page", 2, "learned_interleaving"),
    ]
    learned_cache: dict[int, tuple[list[list[int]], dict[int, int], dict[str, str]]] = {}
    learned_dump: list[str] = []
    metrics = []
    for label, param, grouping_mode in rows:
        if grouping_mode == "contiguous":
            host_groups, victim_group_by_line = build_contiguous_partition(param)
            grouping_note = "contiguous"
        else:
            if param not in learned_cache:
                learned_cache[param] = learn_interleaving_partition(
                    same_labels, same_matrix, param
                )
            host_groups, victim_group_by_line, learn_meta = learned_cache[param]
            grouping_note = "learned_interleaving"
            learned_dump.extend(
                [
                    f"[{label}]",
                    f"group_count={param}",
                    f"alignment_score={learn_meta['alignment_score']}",
                    learn_meta["victim_groups"],
                    learn_meta["host_groups"],
                ]
            )

        m = compute_granularity_metrics(
            same_labels,
            same_matrix,
            other_matrix,
            host_groups=host_groups,
            victim_group_by_line=victim_group_by_line,
        )
        m["granularity"] = label
        m["grouping_mode"] = grouping_note
        m["group_count"] = len(host_groups)
        metrics.append(m)

    if learned_dump:
        write_meta(outdir / "interleaving_groups_43d.txt", learned_dump)

    csv_path = outdir / "granularity_degradation.csv"
    with csv_path.open("w", newline="") as fp:
        wr = csv.writer(fp)
        wr.writerow(
            [
                "granularity",
                "unit_size_lines",
                "h0_mean",
                "h1_mean",
                "delta",
                "localization_accuracy",
                "grouping_mode",
                "group_count",
                "samples_per_class",
            ]
        )
        for m in metrics:
            wr.writerow(
                [
                    m["granularity"],
                    int(m["unit_size"]),
                    f"{m['h0_mean']:.6f}",
                    f"{m['h1_mean']:.6f}",
                    f"{m['delta']:.6f}",
                    f"{m['localization_accuracy']:.6f}",
                    m["grouping_mode"],
                    int(m["group_count"]),
                    int(m["samples_per_class"]),
                ]
            )

    txt_lines = [
        "experiment=4.3-D",
        "purpose=signal_granularity_degradation",
        f"capture_dir={capture_dir}",
        f"reps={args.reps}",
        f"qemu_cpu={args.qemu_cpu}",
        f"host_cpu={args.host_cpu}",
    ]
    for m in metrics:
        txt_lines.extend(
            [
                f"[{m['granularity']}]",
                f"unit_size_lines={int(m['unit_size'])}",
                f"h0_mean={m['h0_mean']:.6f}",
                f"h1_mean={m['h1_mean']:.6f}",
                f"delta={m['delta']:.6f}",
                f"localization_accuracy={m['localization_accuracy']:.6f}",
                f"grouping_mode={m['grouping_mode']}",
                f"group_count={int(m['group_count'])}",
            ]
        )
    write_meta(outdir / "stats_43d.txt", txt_lines)

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        labels = [m["granularity"] for m in metrics]
        loc_accs = [m["localization_accuracy"] for m in metrics]

        fig, ax = plt.subplots(figsize=(7.2, 4.2))
        x = list(range(len(labels)))
        ax.plot(x, loc_accs, marker="o", linewidth=2, label="Localization Accuracy")
        ax.set_xticks(x)
        ax.set_xticklabels(labels, rotation=0)
        ax.set_ylim(0.0, 1.05)
        ax.set_ylabel("Localization Accuracy")
        ax.set_title("4.3-D Signal Degradation vs Granularity")
        ax.grid(True, linestyle=":", alpha=0.5)
        ax.legend()
        fig.tight_layout()
        fig.savefig(outdir / "granularity_degradation.png", dpi=300)
        plt.close(fig)
    except Exception as e:
        write_meta(outdir / "plot_43d_error.txt", [f"plot_failed={e}"])

    print(f"[4.3-D] done: {csv_path}")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="Chapter 4.3 experiment runner")
    sub = ap.add_subparsers(dest="exp", required=True)

    def add_common(p: argparse.ArgumentParser):
        p.add_argument("--outdir", default="")
        p.add_argument("--reps", type=int, default=20000)
        p.add_argument("--victim-line", type=int, default=23)
        p.add_argument("--qemu-cpu", type=int, default=32)
        p.add_argument("--host-cpu", type=int, default=33)
        p.add_argument("--mem", default="4G")
        p.add_argument("--smp", default="1")
        p.add_argument("--skip-build", action="store_true")

    p_a = sub.add_parser("a", help="Run experiment 4.3-A")
    add_common(p_a)
    p_a.add_argument("--noise-vms", type=int, default=2, choices=[2, 3])
    p_a.add_argument("--noise-base-cpu", type=int, default=34)
    p_a.set_defaults(func=run_43a)

    p_b = sub.add_parser("b", help="Run experiment 4.3-B")
    add_common(p_b)
    p_b.set_defaults(func=run_43b)

    p_d = sub.add_parser("d", help="Run experiment 4.3-D")
    add_common(p_d)
    p_d.set_defaults(func=run_43d)

    p_e = sub.add_parser("e", help="Run experiment 4.3-E")
    add_common(p_e)
    p_e.add_argument("--interleave-label", required=True, help="Current BIOS interleaving label, e.g. 256B")
    p_e.add_argument("--pattern-reps", type=int, default=32)
    p_e.add_argument(
        "--pattern-threshold",
        type=float,
        default=None,
        help="Binary pattern threshold. Default: adaptive 95th percentile of same_page_matrix.csv",
    )
    p_e.add_argument("--contention-sync-us", type=int, default=1)
    p_e.set_defaults(func=run_43e)
    return ap


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
