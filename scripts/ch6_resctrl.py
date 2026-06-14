#!/usr/bin/env python3
from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from pathlib import Path


RESCTRL_ROOT = Path("/sys/fs/resctrl")


def ensure_resctrl_mounted() -> None:
    if (RESCTRL_ROOT / "schemata").exists():
        return
    RESCTRL_ROOT.mkdir(parents=True, exist_ok=True)
    cp = subprocess.run(["mount", "-t", "resctrl", "resctrl", str(RESCTRL_ROOT)], check=False, capture_output=True, text=True)
    if cp.returncode != 0 and not (RESCTRL_ROOT / "schemata").exists():
        raise RuntimeError(f"mount resctrl failed: {cp.stderr.strip() or cp.stdout.strip()}")


def parse_root_domains() -> list[int]:
    schemata = (RESCTRL_ROOT / "schemata").read_text()
    m = re.search(r"^L3:([^\n]+)$", schemata, flags=re.M)
    if not m:
        return [0]
    domains = []
    for item in m.group(1).split(";"):
        if "=" not in item:
            continue
        dom, _mask = item.split("=", 1)
        try:
            domains.append(int(dom, 0))
        except ValueError:
            continue
    return domains or [0]


def read_l3_cbm_mask() -> int:
    path = RESCTRL_ROOT / "info" / "L3" / "cbm_mask"
    if not path.exists():
        raise RuntimeError("resctrl L3 cbm_mask not available")
    return int(path.read_text().strip(), 16)


def split_cbm_mask(mask: int) -> tuple[int, int]:
    bits = [i for i in range(mask.bit_length()) if mask & (1 << i)]
    if len(bits) < 2:
        raise RuntimeError(f"cbm_mask too small for split: 0x{mask:x}")
    half = len(bits) // 2
    a_bits = bits[:half]
    b_bits = bits[half:]
    mask_a = 0
    mask_b = 0
    for b in a_bits:
        mask_a |= 1 << b
    for b in b_bits:
        mask_b |= 1 << b
    return mask_a, mask_b


def write_group_schemata(group_dir: Path, *, l3_mask: int, mba_percent: int | None = None, domains: list[int] | None = None) -> None:
    if domains is None:
        domains = parse_root_domains()
    lines = []
    l3_line = "L3:" + ";".join(f"{dom}={l3_mask:x}" for dom in domains)
    lines.append(l3_line)
    if mba_percent is not None:
        mba_percent = max(1, min(100, int(mba_percent)))
        lines.append("MB:" + ";".join(f"{dom}={mba_percent}" for dom in domains))
    (group_dir / "schemata").write_text("\n".join(lines) + "\n")


def create_group(name: str, *, l3_mask: int, mba_percent: int | None = None) -> Path:
    ensure_resctrl_mounted()
    group_dir = RESCTRL_ROOT / name
    group_dir.mkdir(exist_ok=True)
    write_group_schemata(group_dir, l3_mask=l3_mask, mba_percent=mba_percent)
    return group_dir


def assign_tids(group_dir: Path, tids: list[int]) -> None:
    tasks_path = group_dir / "tasks"
    for tid in sorted(set(int(t) for t in tids if int(t) > 0)):
        if not Path("/proc") .joinpath(str(tid)).exists():
            continue
        try:
            with tasks_path.open("w") as fp:
                fp.write(f"{tid}\n")
        except ProcessLookupError:
            continue
        except OSError as e:
            if getattr(e, "errno", None) == 3:  # ESRCH
                continue
            raise


def list_process_threads(pid: int) -> list[tuple[int, str]]:
    task_dir = Path("/proc") / str(int(pid)) / "task"
    rows = []
    for ent in sorted(task_dir.iterdir(), key=lambda p: int(p.name)):
        try:
            comm = (ent / "comm").read_text().strip()
            rows.append((int(ent.name), comm))
        except Exception:
            continue
    return rows


def filter_live_tids(tids: list[int]) -> list[int]:
    return [int(t) for t in tids if int(t) > 0 and (Path("/proc") / str(int(t))).exists()]


def select_vcpu_tids(pid: int) -> list[int]:
    rows = list_process_threads(pid)
    out = []
    for tid, comm in rows:
        low = comm.lower()
        if (
            "cpu " in low
            or "cpu/" in low
            or "kvm" in low
            or "vcpu" in low
            or re.search(r"cpu\\s*\\d", low)
        ):
            out.append(int(tid))
    return sorted(set(out))


def wait_for_vcpu_tids(pid: int, timeout_s: float = 15.0) -> tuple[list[int], list[tuple[int, str]]]:
    deadline = time.time() + float(timeout_s)
    last_rows: list[tuple[int, str]] = []
    while time.time() < deadline:
        last_rows = list_process_threads(pid)
        tids = select_vcpu_tids(pid)
        if tids:
            return tids, last_rows
        time.sleep(0.2)
    return [], last_rows


def wait_for_tid_file(path: Path, timeout_s: float = 15.0) -> int | None:
    deadline = time.time() + float(timeout_s)
    while time.time() < deadline:
        if path.exists():
            try:
                return int(path.read_text().strip())
            except Exception:
                pass
        time.sleep(0.1)
    return None


def cleanup_groups(prefix: str) -> None:
    if not RESCTRL_ROOT.exists():
        return
    for p in sorted(RESCTRL_ROOT.glob(f"{prefix}*"), reverse=True):
        if p.is_dir():
            shutil.rmtree(p, ignore_errors=True)
