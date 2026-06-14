#!/usr/bin/env python3
"""
exp42_fourway_analysis.py — 实验 4.2.4: 四路对比

四组数据：
  H0       : §4.2.1 基线（raw_h0_cycles.csv）
  H1_coh   : §4.2.1 一致性信号（raw_h1_coh_cycles.csv 或 raw_h1_cycles.csv）
  H1_cont  : 仅竞争信号（raw_h1_cont_cycles.csv）
  H1_cmb   : 一致性+竞争联合（raw_h1_cmb_cycles.csv）

输出：
  - tab:stats_fourway  统计量表（stats_42_fourway.txt）
  - fig:fourway_42c    四路分布图（exp42_fourway_hist.png）
  - CCDF 对比图（exp42_fourway_ccdf.png）
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
plt.rcParams["font.size"] = 12

TAIL_THRESHOLDS = [300, 400, 500, 600, 700]


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


def remove_outliers(a: np.ndarray, lo: float = 0.5, hi: float = 99.5,
                    cap: float = 100000.0) -> np.ndarray:
    a = a[a <= cap]
    if a.size == 0:
        return a
    return a[(a >= np.percentile(a, lo)) & (a <= np.percentile(a, hi))]


def describe(name: str, raw: np.ndarray) -> dict:
    c = remove_outliers(raw)
    tails = {t: float(np.mean(raw > t)) for t in TAIL_THRESHOLDS}
    return {
        "name": name,
        "n": raw.size,
        "mean": float(np.mean(c)) if c.size else float("nan"),
        "median": float(np.median(c)) if c.size else float("nan"),
        "std": float(np.std(c)) if c.size else float("nan"),
        "tails": tails,
        "_clean": c,
        "_raw": raw,
    }


def mw_p(a: np.ndarray, b: np.ndarray) -> float:
    if scipy_stats is None or a.size == 0 or b.size == 0:
        return float("nan")
    _, p = scipy_stats.mannwhitneyu(b, a, alternative="two-sided")
    return float(p)


def plot_fourway_hist(groups: list[dict], out_path: Path) -> None:
    colors = ["steelblue", "#2ca02c", "darkorange", "crimson"]
    all_clean = [g["_clean"] for g in groups if g["_clean"].size > 0]
    if not all_clean:
        return
    lo = min(c.min() for c in all_clean)
    hi = max(c.max() for c in all_clean)
    bins = np.linspace(lo, hi, 130)

    fig, ax = plt.subplots(figsize=(11, 5.5))
    for g, col in zip(groups, colors):
        c = g["_clean"]
        if c.size == 0:
            continue
        ax.hist(c, bins=bins, alpha=0.45, color=col, density=True,
                label=f"{g['name']}  (mean={g['mean']:.0f} cyc, n={g['n']})")
        ax.axvline(g["mean"], color=col, linestyle="--", linewidth=1.6)

    for thresh, ls in [(400, ":"), (600, "-.")]:
        ax.axvline(thresh, color="gray", linestyle=ls, linewidth=1.1,
                   label=f"threshold={thresh}")

    ax.set_title("Exp 4.2.4: Four-way Latency Comparison\n"
                 "H0 / H1_coh / H1_cont / H1_cmb")
    ax.set_xlabel("Latency (cycles)")
    ax.set_ylabel("Density")
    ax.grid(True, linestyle=":", alpha=0.5)
    ax.legend(fontsize=9)
    fig.tight_layout()
    fig.savefig(out_path, dpi=300)
    plt.close(fig)


def plot_ccdf(groups: list[dict], out_path: Path) -> None:
    colors = ["steelblue", "#2ca02c", "darkorange", "crimson"]
    all_clean = [g["_clean"] for g in groups if g["_clean"].size > 0]
    if not all_clean:
        return
    lo = min(c.min() for c in all_clean)
    hi = max(c.max() for c in all_clean)
    xs = np.linspace(lo, hi, 1000)

    fig, axes = plt.subplots(1, 2, figsize=(13, 5))

    for ax_idx, (ax, x_lo) in enumerate(zip(axes, [lo, 300.0])):
        mask = xs >= x_lo
        for g, col in zip(groups, colors):
            c = g["_clean"]
            if c.size == 0:
                continue
            ccdf = np.array([np.mean(c > x) for x in xs[mask]])
            ax.plot(xs[mask], ccdf * 100, color=col, linewidth=2,
                    label=g["name"])
        for thresh in [400, 600]:
            ax.axvline(thresh, color="gray", linestyle=":", linewidth=1.0)
        ax.set_xlabel("Latency threshold (cycles)")
        ax.set_ylabel("P(latency > threshold) [%]")
        title = "CCDF (full range)" if ax_idx == 0 else "CCDF (tail, >300 cyc)"
        ax.set_title(title)
        ax.grid(True, linestyle=":", alpha=0.5)
        ax.legend(fontsize=9)

    fig.suptitle("Exp 4.2.4: Four-way CCDF Comparison", fontsize=13)
    fig.tight_layout()
    fig.savefig(out_path, dpi=300)
    plt.close(fig)


def write_stats(groups: list[dict], h0: dict, out_path: Path) -> None:
    lines = [
        "[Exp 4.2.4: Four-way Comparison — tab:stats_fourway]",
        "",
        f"  {'Group':<18} {'n':>7}  {'mean':>8}  {'median':>8}  {'std':>7}  "
        + "  ".join(f"P(>{t})" for t in TAIL_THRESHOLDS),
    ]
    for g in groups:
        tail_str = "  ".join(f"{g['tails'][t]*100:6.3f}%" for t in TAIL_THRESHOLDS)
        lines.append(
            f"  {g['name']:<18} {g['n']:>7}  {g['mean']:>8.2f}  "
            f"{g['median']:>8.2f}  {g['std']:>7.2f}  {tail_str}"
        )

    lines += ["", "  Pairwise vs H0 (Mann-Whitney p, Δ_mean, SNR=Δ/σ_H0):"]
    sigma_h0 = h0["std"]
    for g in groups[1:]:
        p = mw_p(h0["_raw"], g["_raw"])
        delta = g["mean"] - h0["mean"]
        snr = delta / sigma_h0 if sigma_h0 > 0 else float("nan")
        lines.append(
            f"    H0 vs {g['name']:<14}: Δ={delta:+.2f} cyc  SNR={snr:.4f}  MW p={p:.3e}"
        )

    lines += ["", "  Tail ratio vs H0:"]
    for t in TAIL_THRESHOLDS:
        row = f"    >{t} cyc: " + "  ".join(
            f"{g['name']}={g['tails'][t]*100:.3f}%" for g in groups
        )
        lines.append(row)

    text = "\n".join(lines) + "\n"
    print(text)
    out_path.write_text(text)


def resolve_paths(data_dir: Path) -> dict[str, Path | None]:
    def try_paths(*candidates: Path) -> Path | None:
        for p in candidates:
            if p.exists():
                return p
        return None

    return {
        "h0": try_paths(data_dir / "raw_h0_cycles.csv"),
        "h1_coh": try_paths(
            data_dir / "raw_h1_coh_cycles.csv",
            data_dir / "raw_h1_cycles.csv",
        ),
        "h1_cont": try_paths(
            data_dir / "raw_h1_cont_cycles.csv",
            data_dir / "h1_cont" / "raw_h1_cycles.csv",
        ),
        "h1_cmb": try_paths(
            data_dir / "raw_h1_cmb_cycles.csv",
            data_dir / "h1_cmb" / "raw_h1_cycles.csv",
        ),
    }


def main() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    default_dir = repo_root / "result/ch4/exp4_2_fourway"

    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=str(default_dir))
    ap.add_argument("--out", default=None)
    # 可选：单独指定各组数据路径
    ap.add_argument("--h0", default=None)
    ap.add_argument("--h1-coh", default=None)
    ap.add_argument("--h1-cont", default=None)
    ap.add_argument("--h1-cmb", default=None)
    args = ap.parse_args()

    data_dir = Path(args.dir).expanduser().resolve()
    out_dir = Path(args.out).expanduser().resolve() if args.out else data_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    paths = resolve_paths(data_dir)
    # 命令行覆盖
    for key, cli_val in [("h0", args.h0), ("h1_coh", args.h1_coh),
                          ("h1_cont", args.h1_cont), ("h1_cmb", args.h1_cmb)]:
        if cli_val:
            paths[key] = Path(cli_val).expanduser().resolve()

    print("=== 4.2.4 Four-way Analysis ===")
    for k, p in paths.items():
        print(f"  {k}: {p}")

    missing = [k for k, p in paths.items() if p is None]
    if missing:
        print(f"[!] missing data for: {missing}")
        print("    Run run_42_fourway.py first, or supply --h0/--h1-coh/--h1-cont/--h1-cmb")
        if "h0" in missing or "h1_cont" in missing:
            raise SystemExit("Cannot proceed without H0 and H1_cont.")

    groups = []
    labels = [("h0", "H0 baseline"), ("h1_coh", "H1_coh"),
              ("h1_cont", "H1_cont"), ("h1_cmb", "H1_cmb")]
    for key, label in labels:
        p = paths[key]
        if p is None:
            print(f"  [skip] {label} (no data)")
            continue
        raw = read_cycles(p)
        if raw.size == 0:
            print(f"  [skip] {label} (empty)")
            continue
        groups.append(describe(label, raw))

    if len(groups) < 2:
        raise SystemExit("Need at least H0 and one H1 group.")

    h0_group = groups[0]
    plot_fourway_hist(groups, out_dir / "exp42_fourway_hist.png")
    plot_ccdf(groups, out_dir / "exp42_fourway_ccdf.png")
    write_stats(groups, h0_group, out_dir / "stats_42_fourway.txt")
    print(f"outputs: {out_dir}")


if __name__ == "__main__":
    main()
