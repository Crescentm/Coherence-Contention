#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
from pathlib import Path

from experiment_common import REPO_ROOT, dir_stamp, now


RESULT_CH5 = REPO_ROOT / "result" / "ch5"


def timestamped_outdir_ch5(exp_name: str) -> Path:
    return RESULT_CH5 / f"{exp_name}_{dir_stamp()}"


def write_lines(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n")


def write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n")


def _capture(cmd: list[str]) -> dict[str, str | int]:
    cp = subprocess.run(cmd, check=False, capture_output=True, text=True)
    out = (cp.stdout or "").strip()
    err = (cp.stderr or "").strip()
    text = out if out else err
    return {
        "cmd": " ".join(cmd),
        "returncode": cp.returncode,
        "output": text,
    }


def collect_host_facts(outdir: Path) -> Path:
    facts = {
        "generated_at": now(),
        "host": {
            "uname": _capture(["uname", "-a"]),
            "python": _capture(["python3", "--version"]),
            "openssl": _capture(["openssl", "version", "-a"]),
            "lscpu": _capture(["lscpu"]),
            "git_head": _capture(["git", "rev-parse", "--short", "HEAD"]),
            "git_status_short": _capture(["git", "status", "--short"]),
        },
    }
    out = outdir / "host_facts.json"
    write_json(out, facts)
    return out


def seed_51a_layout(outdir: Path) -> list[Path]:
    dirs = [
        outdir / "aes_noasm",
        outdir / "aes_aesni",
        outdir / "rsa_var_time",
        outdir / "rsa_const_time",
        outdir / "smoke_vm",
        outdir / "logs",
    ]
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)
    return dirs
