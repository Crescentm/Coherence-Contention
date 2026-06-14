#!/usr/bin/env python3
from __future__ import annotations

import argparse
import shutil
from pathlib import Path

from experiment_common import (
    RESULT_CH4,
    SRC_DIR,
    print_banner,
    require_root,
    run_checked,
    timestamped_outdir,
)


def main():
    ap = argparse.ArgumentParser(
        description="Experiment 4.1-C: host-only C-bit cross-domain coherence eviction validation."
    )
    ap.add_argument("--cbit-pos", type=int, default=51)
    ap.add_argument("--reps", type=int, default=10000)
    ap.add_argument("--outdir", default="")
    args = ap.parse_args()

    require_root("[!] Please run as root, e.g. sudo -E python3 scripts/run_41c.py")

    outdir = (
        Path(args.outdir).resolve()
        if args.outdir
        else timestamped_outdir("exp4_1_c", RESULT_CH4)
    )
    outdir.mkdir(parents=True, exist_ok=True)
    print_banner("Experiment 4.1-C: Host-only C-bit validation", outdir)

    kmod_dir = SRC_DIR / "kmod_cbit"
    run_checked(["make"], cwd=kmod_dir)
    run_checked(["rmmod", "dev_cbit"], check=False)
    run_checked(["insmod", str(kmod_dir / "dev_cbit.ko")])

    bin_path = SRC_DIR / "exp41c_host_only"
    run_checked(["gcc", "-O2", str(SRC_DIR / "exp41c_host_only.c"), "-o", str(bin_path)])
    run_checked([str(bin_path), str(args.cbit_pos), str(args.reps)], cwd=SRC_DIR)

    run_checked(["rmmod", "dev_cbit"], check=False)

    h0 = SRC_DIR / "host_only_h0.csv"
    h1 = SRC_DIR / "host_only_h1.csv"
    if h0.exists():
        shutil.move(str(h0), str(outdir / h0.name))
    if h1.exists():
        shutil.move(str(h1), str(outdir / h1.name))

    print("\n=== 4.1-C completed ===")
    print(f"data dir: {outdir}")
    print(f"analysis: python3 {SRC_DIR / 'analyze' / 'exp41c_analysis.py'}")


if __name__ == "__main__":
    main()
