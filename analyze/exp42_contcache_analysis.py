#!/usr/bin/env python3
"""
exp42_contcache_analysis.py — 实验 4.2.3.2: Cacheable 路径竞争信号分析

输出：
  - 分布图（KDE + 直方图）
  - 统计量：均值、中位数、σ、P(T>400)
  - stats_42_contcache.txt
"""
from __future__ import annotations

import argparse
import csv
from pathlib import Path

import numpy as np
import matplotlib.pyplot as plt

try:
    from scipy import stats as scipy_stats
except Exception:
    scipy_stats = None

plt.rcParams["font.sans-serif"] = ["DejaVu Sans"]
plt.rcParams["axes.unicode_minus"] = False
plt.rcParams["font.size"] = 13


def read_cycles(path: Path) -> np.ndarray:
    vals = []
    with path.open(newline="") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row:
                continue
            try:
                vals.append(float(row[-1]))
            except ValueError:
                continue
    return np.asarray(vals, dtype=np.float64)


def remove_outliers(a: np.ndarray, lo_pct: float = 0.5, hi_pct: float = 99.5,
                    hard_cap: float = 100000.0) -> np.ndarray:
    a = a[a <= hard_cap]
    if a.size == 0:
        return a
    return a[(a >= np.percentile(a, lo_pct)) & (a <= np.percentile(a, hi_pct))]


def describe(name: str, raw: np.ndarray) -> dict:
    c = remove_outliers(raw)
    p_gt400 = float(np.mean(raw > 400)) if raw.size else float("nan")
    return {
        "name": name,
        "n": raw.size,
        "mean": float(np.mean(c)) if c.size else float("nan"),
        "median": float(np.median(c)) if c.size else float("nan"),
        "std": float(np.std(c)) if c.size else float("nan"),
        "p_gt400": p_gt400,
        "p_gt300": float(np.mean(raw > 300)) if raw.size else float("nan"),
        "p_gt500": float(np.mean(raw > 500)) if raw.size else float("nan"),
    }


def plot_dist(h0: np.ndarray, h1: np.ndarray, out_path: Path) -> None:
    h0c = remove_outliers(h0)
    h1c = remove_outliers(h1)
    if h0c.size == 0 or h1c.size == 0:
        return

    lo = min(h0c.min(), h1c.min())
    hi = max(h0c.max(), h1c.max())
    bins = np.linspace(lo, hi, 120)

    fig, ax = plt.subplots(figsize=(10, 5))
    ax.hist(h0c, bins=bins, alpha=0.55, color="steelblue", density=True,
            label=f"H0 baseline  (mean={np.mean(h0c):.0f} cyc)")
    ax.hist(h1c, bins=bins, alpha=0.50, color="crimson", density=True,
            label=f"H1 contention (mean={np.mean(h1c):.0f} cyc)")
    ax.axvline(np.mean(h0c), color="steelblue", linestyle="--", linewidth=1.8)
    ax.axvline(np.mean(h1c), color="crimson", linestyle="--", linewidth=1.8)
    ax.axvline(400, color="gray", linestyle=":", linewidth=1.2, label="threshold=400 cyc")

    p_gt400_h0 = float(np.mean(h0 > 400))
    p_gt400_h1 = float(np.mean(h1 > 400))
    ymax = ax.get_ylim()[1]
    ax.text(405, ymax * 0.72,
            f">400 cyc:\nH0={p_gt400_h0*100:.2f}%\nH1={p_gt400_h1*100:.2f}%",
            fontsize=10, color="black",
            bbox=dict(boxstyle="round,pad=0.3", fc="lightyellow", ec="gray", alpha=0.85))

    ax.set_title("Exp 4.2.3.2: Cacheable Contention Signal\n"
                 "(host CLFLUSH before each probe, guest CLFLUSH+load)")
    ax.set_xlabel("Latency (cycles)")
    ax.set_ylabel("Density")
    ax.grid(True, linestyle=":", alpha=0.5)
    ax.legend(fontsize=10)
    fig.tight_layout()
    fig.savefig(out_path, dpi=300)
    plt.close(fig)


def write_stats(d0: dict, d1: dict, out_path: Path) -> None:
    delta_mean = d1["mean"] - d0["mean"]
    snr = (delta_mean / d0["std"]) if d0["std"] > 0 else float("nan")

    mw_p = float("nan")
    if scipy_stats is not None:
        h0 = d0.get("_raw")
        h1 = d1.get("_raw")
        if h0 is not None and h1 is not None and h0.size > 0 and h1.size > 0:
            _, mw_p = scipy_stats.mannwhitneyu(h1, h0, alternative="two-sided")

    lines = [
        "[Exp 4.2.3.2: Cacheable Contention Signal]",
        "",
        f"  H0 baseline  : n={d0['n']}  mean={d0['mean']:.2f}  median={d0['median']:.2f}  "
        f"std={d0['std']:.2f}  P(>400)={d0['p_gt400']*100:.3f}%",
        f"  H1 contention: n={d1['n']}  mean={d1['mean']:.2f}  median={d1['median']:.2f}  "
        f"std={d1['std']:.2f}  P(>400)={d1['p_gt400']*100:.3f}%",
        "",
        f"  Δ_mean = {delta_mean:.2f} cyc",
        f"  SNR (Δ/σ_H0) = {snr:.4f}",
        f"  Mann-Whitney p = {mw_p:.3e}",
        "",
        "  Tail proportions:",
        f"    P(T>300): H0={d0['p_gt300']*100:.3f}%  H1={d1['p_gt300']*100:.3f}%",
        f"    P(T>400): H0={d0['p_gt400']*100:.3f}%  H1={d1['p_gt400']*100:.3f}%",
        f"    P(T>500): H0={d0['p_gt500']*100:.3f}%  H1={d1['p_gt500']*100:.3f}%",
    ]
    text = "\n".join(lines) + "\n"
    print(text)
    out_path.write_text(text)


def main() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    default_dir = repo_root / "result/ch4/exp4_2_contcache"

    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=str(default_dir))
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    data_dir = Path(args.dir).expanduser().resolve()
    out_dir = Path(args.out).expanduser().resolve() if args.out else data_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    h0_path = data_dir / "raw_h0_cycles.csv"
    h1_path = data_dir / "raw_h1_cycles.csv"
    if not h0_path.exists() or not h1_path.exists():
        raise SystemExit(f"[contcache] missing H0/H1 csv under {data_dir}")

    h0 = read_cycles(h0_path)
    h1 = read_cycles(h1_path)

    d0 = describe("H0 baseline", h0)
    d1 = describe("H1 contention", h1)
    d0["_raw"] = h0
    d1["_raw"] = h1

    plot_dist(h0, h1, out_dir / "exp42_contcache_hist.png")
    write_stats(d0, d1, out_dir / "stats_42_contcache.txt")
    print(f"outputs: {out_dir}")


if __name__ == "__main__":
    main()
