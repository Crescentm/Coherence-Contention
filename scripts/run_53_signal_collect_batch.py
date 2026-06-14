#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from ch5_common import collect_host_facts, timestamped_outdir_ch5, write_json
from experiment_common import print_banner, require_root


SCRIPT_DIR = Path(__file__).resolve().parent
RUN_COLLECT = SCRIPT_DIR / "run_53_signal_collect.py"


def parse_args() -> tuple[argparse.Namespace, list[str]]:
    ap = argparse.ArgumentParser(description="Batch signal collection for Ch5 offline training.", allow_abbrev=False)
    ap.add_argument("--runs", type=int, default=16)
    ap.add_argument("--batch-outdir", default="")
    ap.add_argument("--child-name", default="run")
    ap.add_argument("--stop-on-fail", action="store_true")
    args, child_argv = ap.parse_known_args()
    if child_argv and child_argv[0] == "--":
        child_argv = child_argv[1:]
    return args, child_argv


def main() -> None:
    args, child_argv = parse_args()
    require_root("[!] run_53_signal_collect_batch.py requires root.")

    outdir = Path(args.batch_outdir).resolve() if args.batch_outdir else timestamped_outdir_ch5("exp5_3_signal_batch")
    outdir.mkdir(parents=True, exist_ok=True)
    print_banner(f"Experiment 5.3 Signal Batch ({args.runs} runs)", outdir)
    collect_host_facts(outdir)
    manifest = {"runs": int(args.runs), "batch_outdir": str(outdir), "children": []}

    for i in range(1, int(args.runs) + 1):
        child_out = outdir / f"{args.child_name}_{i:02d}"
        cmd = [sys.executable, str(RUN_COLLECT), *child_argv, "--outdir", str(child_out)]
        if i > 1:
            cmd.append("--skip-build")
        print(f"[batch] run {i}/{args.runs}: {' '.join(cmd)}")
        cp = subprocess.run(cmd, check=False)
        manifest["children"].append(
            {"index": int(i), "outdir": str(child_out), "returncode": int(cp.returncode), "cmd": cmd}
        )
        write_json(outdir / "batch_manifest.json", manifest)
        if cp.returncode != 0 and args.stop_on_fail:
            raise SystemExit(f"[batch] child failed: run={i} rc={cp.returncode}")

    print(f"[batch] done: outdir={outdir}")


if __name__ == "__main__":
    main()
