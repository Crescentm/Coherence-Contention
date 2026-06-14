#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
from pathlib import Path

from experiment_common import (
    RESULT_CH4,
    RUN_EXPERIMENT,
    SRC_DIR,
    ensure_artifacts,
    print_banner,
    run_checked,
    timestamped_outdir,
)


def main():
    ap = argparse.ArgumentParser(
        description="Experiment 4.2-A: high-precision coherence signal capture."
    )
    ap.add_argument("--reps", type=int, default=50000)
    ap.add_argument("--victim-line", type=int, default=0)
    ap.add_argument("--qemu-cpu", type=int, default=32)
    ap.add_argument("--host-cpu", type=int, default=33)
    ap.add_argument("--mem", default="4G")
    ap.add_argument("--smp", default="1")
    ap.add_argument("--skip-build", action="store_true")
    ap.add_argument("--outdir", default="")
    args = ap.parse_args()

    outdir = (
        Path(args.outdir).resolve()
        if args.outdir
        else timestamped_outdir("exp4_2_a", RESULT_CH4)
    )
    print_banner(f"Experiment 4.2-A: coherence capture ({args.reps} reps)", outdir)

    ensure_artifacts(args.skip_build, outdir)
    print("[run] launching run_experiment.py ...")

    env = os.environ.copy()
    env["HR_RAW_FOCUS_VLINE"] = str(args.victim_line)

    run_checked(
        [
            "sudo",
            "-E",
            "python3",
            str(RUN_EXPERIMENT),
            "--reps",
            str(args.reps),
            "--victim-lines",
            str(args.victim_line),
            "--outdir",
            str(outdir),
            "--qemu-cpu",
            str(args.qemu_cpu),
            "--host-cpu",
            str(args.host_cpu),
            "--mem",
            str(args.mem),
            "--smp",
            str(args.smp),
            "--skip-build",
        ],
        cwd=SRC_DIR,
        env=env,
    )

    print("\n=== 4.2-A completed ===")
    print(f"data dir: {outdir}")
    print(
        "analysis: "
        f"python3 {SRC_DIR / 'analyze' / 'exp42a_analysis.py'} --data-dir {outdir}"
    )


if __name__ == "__main__":
    main()
