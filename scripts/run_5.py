#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from ch5_common import (
    RESULT_CH5,
    collect_host_facts,
    timestamped_outdir_ch5,
    write_json,
    write_lines,
)
from experiment_common import ensure_artifacts, print_banner


CH5_TASKS = [
    {"id": "5.1-A", "name": "victim crypto behavior validation", "priority": "P0", "depends_on": []},
    {"id": "5.2-A", "name": "GPA->HPA mapping records", "priority": "P0", "depends_on": ["5.1-A"]},
    {"id": "5.3-A", "name": "AES single-byte recovery PoC", "priority": "P0", "depends_on": ["5.1-A", "5.2-A"]},
    {"id": "5.3-B", "name": "AES full-key recovery", "priority": "P0", "depends_on": ["5.3-A"]},
    {"id": "5.4-A", "name": "RSA square vs multiply separation", "priority": "P0", "depends_on": ["5.1-A", "5.2-A"]},
    {"id": "5.4-B", "name": "RSA key-bit reconstruction", "priority": "P0", "depends_on": ["5.4-A"]},
    {"id": "5.5-A", "name": "multi-load robustness", "priority": "P1", "depends_on": ["5.3-B", "5.4-B"]},
]


def cmd_overview() -> None:
    print("Chapter 5 experiment overview")
    for t in CH5_TASKS:
        deps = ", ".join(t["depends_on"]) if t["depends_on"] else "-"
        print(f"- {t['id']} [{t['priority']}] {t['name']} (depends on: {deps})")


def cmd_bootstrap(args: argparse.Namespace) -> None:
    outdir = (
        Path(args.outdir).resolve()
        if args.outdir
        else timestamped_outdir_ch5("exp5_bootstrap")
    )
    outdir.mkdir(parents=True, exist_ok=True)
    print_banner("Chapter 5 bootstrap", outdir)

    if args.build_base:
        ensure_artifacts(args.skip_build, outdir / "build_stage")

    collect_host_facts(outdir)
    write_json(outdir / "ch5_task_manifest.json", {"tasks": CH5_TASKS})
    write_lines(
        outdir / "next_steps.txt",
        [
            "1) Run 5.1-A bootstrap:",
            "   sudo -E python3 src/scripts/run_51.py",
            "2) Add guest crypto validation workload into initramfs.",
            "3) Collect AES/RSA baseline behavior numbers for section 5.1.",
        ],
    )

    print("\n=== Chapter 5 bootstrap completed ===")
    print(f"data dir: {outdir}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Chapter 5 experiment orchestration bootstrap.")
    sub = ap.add_subparsers(dest="sub", required=False)

    sub.add_parser("overview", help="print chapter-5 task overview")

    p_boot = sub.add_parser("bootstrap", help="create chapter-5 baseline workspace")
    p_boot.add_argument("--outdir", default="")
    p_boot.add_argument("--build-base", action="store_true")
    p_boot.add_argument("--skip-build", action="store_true")

    args = ap.parse_args()
    if args.sub in (None, "overview"):
        cmd_overview()
        return
    if args.sub == "bootstrap":
        cmd_bootstrap(args)
        return
    raise SystemExit(f"unsupported subcommand: {args.sub}")


if __name__ == "__main__":
    main()
