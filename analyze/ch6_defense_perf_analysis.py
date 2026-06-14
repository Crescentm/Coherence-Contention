#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import statistics
from pathlib import Path


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Aggregate Chapter 6 defense performance runs.")
    ap.add_argument("--baseline-dir", required=True)
    ap.add_argument("--defended-dir", required=True)
    ap.add_argument("--out-json", default="")
    return ap.parse_args()


def load_runs(root: Path) -> list[dict]:
    rows = []
    for p in sorted(root.glob("run_*")):
        meta = p / "aes_toggle_analysis.json"
        if not meta.exists():
            meta = p / "aes_perf_analysis.json"
        if not meta.exists():
            continue
        obj = json.loads(meta.read_text())
        rows.append(obj)
    return rows


def summarize(rows: list[dict]) -> dict:
    ns = [
        float(r["guest_ns_per_call"]) if "guest_ns_per_call" in r else float(r["ns_per_call"])
        for r in rows
        if "guest_ns_per_call" in r or "ns_per_call" in r
    ]
    cyc = [
        float(r["guest_cycles_per_call"]) if "guest_cycles_per_call" in r else float(r["cycles_per_call"])
        for r in rows
        if "guest_cycles_per_call" in r or "cycles_per_call" in r
    ]
    sep = [float(r["separation_median"]) for r in rows if "separation_median" in r]
    snr = [float(r["snr"]) for r in rows if "snr" in r]
    return {
        "n": len(rows),
        "guest_ns_per_call_median": statistics.median(ns) if ns else None,
        "guest_ns_per_call_mean": statistics.fmean(ns) if ns else None,
        "guest_cycles_per_call_median": statistics.median(cyc) if cyc else None,
        "guest_cycles_per_call_mean": statistics.fmean(cyc) if cyc else None,
        "signal_sep_median": statistics.median(sep) if sep else None,
        "signal_snr_median": statistics.median(snr) if snr else None,
    }


def main() -> None:
    args = parse_args()
    base_dir = Path(args.baseline_dir).resolve()
    def_dir = Path(args.defended_dir).resolve()
    base_rows = load_runs(base_dir)
    def_rows = load_runs(def_dir)
    base = summarize(base_rows)
    defended = summarize(def_rows)

    slowdown_ratio = None
    slowdown_percent = None
    if base["guest_ns_per_call_median"] and defended["guest_ns_per_call_median"]:
        slowdown_ratio = defended["guest_ns_per_call_median"] / base["guest_ns_per_call_median"]
        slowdown_percent = (slowdown_ratio - 1.0) * 100.0

    out = {
        "baseline_dir": str(base_dir),
        "defended_dir": str(def_dir),
        "baseline": base,
        "defended": defended,
        "slowdown_ratio": slowdown_ratio,
        "slowdown_percent": slowdown_percent,
    }
    if args.out_json:
        Path(args.out_json).write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps(out, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
