#!/usr/bin/env python3
# exp42c_analysis.py
# 分析 4.2-C（一致性 + 竞争综合）实验数据（独立脚本，不依赖 exp42bc_analysis.py）

from __future__ import annotations

import argparse
import csv
from pathlib import Path

import numpy as np
import matplotlib.pyplot as plt

try:
    from scipy import stats as scipy_stats
except Exception:  # pragma: no cover
    scipy_stats = None

plt.rcParams["font.sans-serif"] = ["DejaVu Sans"]
plt.rcParams["axes.unicode_minus"] = False
plt.rcParams["font.size"] = 13
plt.rcParams["axes.titlesize"] = 15


def read_cycles_csv(path: Path) -> np.ndarray:
    vals = []
    with path.open(newline="") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row:
                continue
            raw = row[-1].strip()
            try:
                vals.append(float(raw))
            except ValueError:
                continue
    return np.asarray(vals, dtype=np.float64)


def remove_outliers(series: np.ndarray, lower: float = 0.5, upper: float = 99.5,
                    hard_cap: float = 100000.0) -> np.ndarray:
    series = series[series <= hard_cap]
    if series.size == 0:
        return series
    p_lo = np.percentile(series, lower)
    p_hi = np.percentile(series, upper)
    return series[(series >= p_lo) & (series <= p_hi)]


def statistical_tests(a: np.ndarray, b: np.ndarray) -> tuple[float, float, float]:
    if a.size == 0 or b.size == 0:
        return float("nan"), float("nan"), float("nan")
    if scipy_stats is None:
        return float("nan"), float("nan"), float("nan")

    mw_stat, mw_p = scipy_stats.mannwhitneyu(b, a, alternative="two-sided")
    _, welch_p = scipy_stats.ttest_ind(b, a, equal_var=False)
    n1, n2 = len(b), len(a)
    n = n1 + n2
    mu_u = n1 * n2 / 2.0
    sigma_u = np.sqrt(n1 * n2 * (n + 1) / 12.0)
    z = (mw_stat - mu_u) / sigma_u if sigma_u > 0 else 0.0
    effect_r = min(abs(z) / np.sqrt(n), 1.0)
    return float(mw_p), float(welch_p), float(effect_r)


def describe_group(name: str, data: np.ndarray) -> dict[str, float]:
    clean = remove_outliers(data)
    return {
        "name": name,
        "n_raw": float(len(data)),
        "n_clean": float(len(clean)),
        "removed": float(len(data) - len(clean)),
        "mean": float(np.mean(clean)) if clean.size else float("nan"),
        "std": float(np.std(clean)) if clean.size else float("nan"),
        "median": float(np.median(clean)) if clean.size else float("nan"),
    }


TAIL_THRESHOLDS = [500, 600, 700, 800, 1000]


def tail_proportions(data: np.ndarray, thresholds=TAIL_THRESHOLDS) -> dict[int, float]:
    """Return fraction of samples above each threshold (applied to raw data, no outlier removal)."""
    return {t: float(np.mean(data > t)) for t in thresholds}


def plot_threeway_hist(h0: np.ndarray, coh: np.ndarray, cmb: np.ndarray, out_path: Path) -> None:
    h0_c = remove_outliers(h0)
    coh_c = remove_outliers(coh)
    cmb_c = remove_outliers(cmb)
    if h0_c.size == 0 or coh_c.size == 0 or cmb_c.size == 0:
        return

    lo = min(np.min(h0_c), np.min(coh_c), np.min(cmb_c))
    hi = max(np.max(h0_c), np.max(coh_c), np.max(cmb_c))
    bins = np.linspace(lo, hi, 140)

    fig, ax = plt.subplots(figsize=(10.5, 5.6))
    ax.hist(h0_c, bins=bins, alpha=0.50, color="steelblue", density=True, label="H0 baseline")
    ax.hist(coh_c, bins=bins, alpha=0.45, color="#2ca02c", density=True, label="H1 coherence_only")
    ax.hist(cmb_c, bins=bins, alpha=0.45, color="crimson", density=True, label="H1 combined (blind)")

    for mean_val, color in [(np.mean(h0_c), "steelblue"),
                             (np.mean(coh_c), "#2ca02c"),
                             (np.mean(cmb_c), "crimson")]:
        ax.axvline(mean_val, color=color, linestyle="--", linewidth=1.6)

    # Mark tail thresholds
    for thresh, ls in [(500, ":"), (700, "-.")]:
        ax.axvline(thresh, color="gray", linestyle=ls, linewidth=1.2,
                   label=f"threshold={thresh}")

    ax.set_title("4.2-C: Baseline vs Coherence-only vs Combined (blind concurrent)")
    ax.set_xlabel("Latency (cycles)")
    ax.set_ylabel("Density")
    ax.grid(True, linestyle=":", alpha=0.5)
    ax.legend(fontsize=10)
    fig.tight_layout()
    fig.savefig(out_path, dpi=300)
    plt.close(fig)


def plot_pair_hist(h0: np.ndarray, cmb: np.ndarray, out_path: Path) -> None:
    h0_c = remove_outliers(h0)
    cmb_c = remove_outliers(cmb)
    if h0_c.size == 0 or cmb_c.size == 0:
        return

    lo = min(np.min(h0_c), np.min(cmb_c))
    hi = max(np.max(h0_c), np.max(cmb_c))
    bins = np.linspace(lo, hi, 120)

    fig, ax = plt.subplots(figsize=(9, 5))
    ax.hist(h0_c, bins=bins, alpha=0.55, color="steelblue", density=True, label="H0 (Baseline)")
    ax.hist(cmb_c, bins=bins, alpha=0.55, color="crimson", density=True, label="H1 (Coherence + Contention)")
    ax.axvline(np.mean(h0_c), color="steelblue", linestyle="--", linewidth=1.8)
    ax.axvline(np.mean(cmb_c), color="crimson", linestyle="--", linewidth=1.8)
    for thresh, ls in [(500, ":"), (700, "-.")]:
        ax.axvline(thresh, color="gray", linestyle=ls, linewidth=1.2,
                   label=f"threshold={thresh}")
    ax.set_title("4.2-C: Coherence + Contention Signal")
    ax.set_xlabel("Latency (cycles)")
    ax.set_ylabel("Density")
    ax.grid(True, linestyle=":", alpha=0.5)
    ax.legend(fontsize=11)
    fig.tight_layout()
    fig.savefig(out_path, dpi=300)
    plt.close(fig)


def plot_coh_vs_cmb_hist(coh: np.ndarray, cmb: np.ndarray, out_path: Path) -> None:
    """Focused comparison of coherence_only vs combined distribution.
    Highlights tail-proportion difference -- the primary RRMB signal."""
    coh_c = remove_outliers(coh)
    cmb_c = remove_outliers(cmb)
    if coh_c.size == 0 or cmb_c.size == 0:
        return

    lo = min(np.min(coh_c), np.min(cmb_c))
    hi = max(np.max(coh_c), np.max(cmb_c))
    bins = np.linspace(lo, hi, 120)

    tp_coh = tail_proportions(coh)
    tp_cmb = tail_proportions(cmb)

    fig, ax = plt.subplots(figsize=(10, 5.5))
    ax.hist(coh_c, bins=bins, alpha=0.55, color="#2ca02c", density=True,
            label=f"H1 coherence_only  (sync, mean={np.mean(coh_c):.0f} cyc)")
    ax.hist(cmb_c, bins=bins, alpha=0.45, color="crimson", density=True,
            label=f"H1 combined/blind  (mean={np.mean(cmb_c):.0f} cyc, "
                  f">700cyc: {tp_cmb[700]*100:.1f}% vs {tp_coh[700]*100:.1f}%)")

    ax.axvline(np.mean(coh_c), color="#2ca02c", linestyle="--", linewidth=1.6)
    ax.axvline(np.mean(cmb_c), color="crimson", linestyle="--", linewidth=1.6)
    ax.axvline(700, color="black", linestyle="-.", linewidth=1.4, label="threshold=700 cyc")

    ymax = ax.get_ylim()[1]
    ax.text(705, ymax * 0.75,
            f">700 cyc:\ncoh={tp_coh[700]*100:.1f}%\ncmb={tp_cmb[700]*100:.1f}%",
            fontsize=10, color="black",
            bbox=dict(boxstyle="round,pad=0.3", fc="lightyellow", ec="gray", alpha=0.85))

    ax.set_title("4.2-C: Coherence-only vs Combined (blind concurrent)\n"
                 "Key signal: higher fraction of extreme-latency samples in combined")
    ax.set_xlabel("Latency (cycles)")
    ax.set_ylabel("Density")
    ax.grid(True, linestyle=":", alpha=0.5)
    ax.legend(fontsize=10)
    fig.tight_layout()
    fig.savefig(out_path, dpi=300)
    plt.close(fig)


def plot_ccdf(coh: np.ndarray, cmb: np.ndarray, out_path: Path) -> None:
    """Complementary CDF (survival function) comparison.
    Shows the tail divergence between coherence_only and combined."""
    coh_c = remove_outliers(coh)
    cmb_c = remove_outliers(cmb)
    if coh_c.size == 0 or cmb_c.size == 0:
        return

    lo = min(np.min(coh_c), np.min(cmb_c))
    hi = max(np.max(coh_c), np.max(cmb_c))
    xs = np.linspace(lo, hi, 1000)

    ccdf_coh = np.array([np.mean(coh_c > x) for x in xs])
    ccdf_cmb = np.array([np.mean(cmb_c > x) for x in xs])

    fig, axes = plt.subplots(1, 2, figsize=(13, 5))

    # Left: linear scale
    ax = axes[0]
    ax.plot(xs, ccdf_coh * 100, color="#2ca02c", linewidth=2, label="H1 coherence_only")
    ax.plot(xs, ccdf_cmb * 100, color="crimson", linewidth=2, label="H1 combined (blind)")
    for thresh in [500, 700]:
        ax.axvline(thresh, color="gray", linestyle=":", linewidth=1.0)
    ax.set_xlabel("Latency threshold (cycles)")
    ax.set_ylabel("P(latency > threshold) [%]")
    ax.set_title("CCDF: Survival Function (linear)")
    ax.grid(True, linestyle=":", alpha=0.5)
    ax.legend(fontsize=10)

    # Right: zoomed into tail region (>400 cycles)
    mask = xs >= 400
    ax2 = axes[1]
    ax2.plot(xs[mask], ccdf_coh[mask] * 100, color="#2ca02c", linewidth=2, label="H1 coherence_only")
    ax2.plot(xs[mask], ccdf_cmb[mask] * 100, color="crimson", linewidth=2, label="H1 combined (blind)")
    ax2.fill_between(xs[mask], ccdf_coh[mask] * 100, ccdf_cmb[mask] * 100,
                     where=(ccdf_cmb[mask] >= ccdf_coh[mask]),
                     alpha=0.18, color="crimson", label="combined excess tail")
    for thresh in [500, 700]:
        ax2.axvline(thresh, color="gray", linestyle=":", linewidth=1.0, label=f"t={thresh}")
    ax2.set_xlabel("Latency threshold (cycles)")
    ax2.set_ylabel("P(latency > threshold) [%]")
    ax2.set_title("CCDF: Tail Region (>400 cycles)")
    ax2.grid(True, linestyle=":", alpha=0.5)
    ax2.legend(fontsize=9)

    fig.suptitle("4.2-C: Coherence-only vs Combined -- Complementary CDF", fontsize=14)
    fig.tight_layout()
    fig.savefig(out_path, dpi=300)
    plt.close(fig)


def plot_tail_bar(coh: np.ndarray, cmb: np.ndarray, out_path: Path) -> None:
    """Bar chart of tail proportions at multiple thresholds."""
    tp_coh = tail_proportions(coh)
    tp_cmb = tail_proportions(cmb)

    thresholds = TAIL_THRESHOLDS
    x = np.arange(len(thresholds))
    width = 0.35

    coh_vals = [tp_coh[t] * 100 for t in thresholds]
    cmb_vals = [tp_cmb[t] * 100 for t in thresholds]

    fig, ax = plt.subplots(figsize=(9, 5))
    bars_coh = ax.bar(x - width / 2, coh_vals, width, color="#2ca02c",
                      alpha=0.8, label="H1 coherence_only")
    bars_cmb = ax.bar(x + width / 2, cmb_vals, width, color="crimson",
                      alpha=0.8, label="H1 combined (blind)")

    # Annotate ratio
    for xi, (cv, mv) in enumerate(zip(coh_vals, cmb_vals)):
        ratio = mv / cv if cv > 0 else float("nan")
        if np.isfinite(ratio):
            ax.text(xi + width / 2, mv + max(cmb_vals) * 0.015,
                    f"{ratio:.1f}x", ha="center", va="bottom", fontsize=9, color="darkred")

    ax.set_xticks(x)
    ax.set_xticklabels([f">{t}" for t in thresholds])
    ax.set_xlabel("Latency threshold")
    ax.set_ylabel("Fraction of samples [%]")
    ax.set_title("4.2-C: Tail Proportion -- coherence_only vs combined (blind)\n"
                 "Combined has higher fraction of extreme-latency events (contention collisions)")
    ax.legend(fontsize=10)
    ax.grid(True, axis="y", linestyle=":", alpha=0.6)
    fig.tight_layout()
    fig.savefig(out_path, dpi=300)
    plt.close(fig)


def write_stats(h0: np.ndarray, coh: np.ndarray, cmb: np.ndarray, out_path: Path) -> None:
    h0_c = remove_outliers(h0)
    coh_c = remove_outliers(coh)
    cmb_c = remove_outliers(cmb)
    if h0_c.size == 0 or coh_c.size == 0 or cmb_c.size == 0:
        out_path.write_text("[4.2-C] no valid data after filtering\n")
        return

    d0 = describe_group("H0 baseline", h0)
    d1 = describe_group("H1 coherence_only", coh)
    d2 = describe_group("H1 combined", cmb)

    mw_01, w_01, r_01 = statistical_tests(h0_c, coh_c)
    mw_02, w_02, r_02 = statistical_tests(h0_c, cmb_c)
    mw_12, w_12, r_12 = statistical_tests(coh_c, cmb_c)

    delta_01 = d1["mean"] - d0["mean"]
    delta_02 = d2["mean"] - d0["mean"]
    delta_12 = d2["mean"] - d1["mean"]

    snr_01 = delta_01 / d0["std"] if d0["std"] > 0 else float("nan")
    snr_02 = delta_02 / d0["std"] if d0["std"] > 0 else float("nan")
    snr_12 = delta_12 / d1["std"] if d1["std"] > 0 else float("nan")

    # Percentile table
    def pct_row(arr: np.ndarray) -> str:
        p = np.percentile(arr, [25, 50, 75, 90, 95, 99])
        return (f"P25={p[0]:.0f}  P50={p[1]:.0f}  P75={p[2]:.0f}  "
                f"P90={p[3]:.0f}  P95={p[4]:.0f}  P99={p[5]:.0f}")

    # Tail proportions (computed on raw data to avoid truncation artifact)
    tp0 = tail_proportions(h0)
    tp1 = tail_proportions(coh)
    tp2 = tail_proportions(cmb)

    def tp_row(tp: dict[int, float]) -> str:
        return "  ".join(f">{t}cyc={tp[t]*100:.2f}%" for t in TAIL_THRESHOLDS)

    lines = [
        "[4.2-C Combined Analysis]",
        "",
        "  Group Stats",
        f"  H0 baseline       : n={int(d0['n_clean'])} (removed {int(d0['removed'])}), mean={d0['mean']:.2f}, std={d0['std']:.2f}, median={d0['median']:.2f}",
        f"  H1 coherence_only : n={int(d1['n_clean'])} (removed {int(d1['removed'])}), mean={d1['mean']:.2f}, std={d1['std']:.2f}, median={d1['median']:.2f}",
        f"  H1 combined       : n={int(d2['n_clean'])} (removed {int(d2['removed'])}), mean={d2['mean']:.2f}, std={d2['std']:.2f}, median={d2['median']:.2f}",
        "",
        "  Percentile Distribution",
        f"  H0 baseline       : {pct_row(h0_c)}",
        f"  H1 coherence_only : {pct_row(coh_c)}",
        f"  H1 combined       : {pct_row(cmb_c)}",
        "",
        "  Tail Proportions (fraction of samples above threshold)",
        f"  H0 baseline       : {tp_row(tp0)}",
        f"  H1 coherence_only : {tp_row(tp1)}",
        f"  H1 combined       : {tp_row(tp2)}",
        "",
        "  Tail Ratio combined/coherence_only  -- key RRMB signal",
    ] + [
        f"    >{t} cyc: coh={tp1[t]*100:.2f}%  cmb={tp2[t]*100:.2f}%  "
        f"ratio={tp2[t]/tp1[t]:.2f}x"
        if tp1[t] > 0 else f"    >{t} cyc: (coherence_only=0, skip)"
        for t in TAIL_THRESHOLDS
    ] + [
        "",
        "  Pairwise Mean Comparison",
        f"  baseline vs coherence_only : Δ={delta_01:.2f} cyc, SNR={snr_01:.3f}, MW p={mw_01:.3e}, Welch p={w_01:.3e}, r={r_01:.4f}",
        f"  baseline vs combined       : Δ={delta_02:.2f} cyc, SNR={snr_02:.3f}, MW p={mw_02:.3e}, Welch p={w_02:.3e}, r={r_02:.4f}",
        f"  coherence_only vs combined : Δ={delta_12:.2f} cyc, SNR={snr_12:.3f}, MW p={mw_12:.3e}, Welch p={w_12:.3e}, r={r_12:.4f}",
        "",
        "  Note: combined (blind) signal manifests as heavier extreme-latency tail",
        "  (higher >700cyc fraction), not as higher mean.  This matches RRMB",
        "  case-m-loop: contention spikes occur only when host ioctl collides with",
        "  guest's concurrent access to the same 64B block.",
    ]
    text = "\n".join(lines) + "\n"
    print(text)
    out_path.write_text(text)


def resolve_input_paths(data_dir: Path) -> tuple[Path | None, Path | None, Path | None]:
    # baseline
    h0 = data_dir / "h0_baseline" / "raw_cycles.csv"
    if not h0.exists():
        h0 = data_dir / "raw_h0_cycles.csv"
    if not h0.exists():
        h0 = None

    # coherence only（42c关键）
    coh = data_dir / "h1_coherence_only" / "raw_cycles.csv"
    if not coh.exists():
        coh = None

    # combined
    cmb = data_dir / "h1_combined" / "raw_cycles.csv"
    if not cmb.exists():
        cmb = data_dir / "raw_h1_cycles.csv"
    if not cmb.exists():
        cmb = None

    return h0, coh, cmb


def main() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    default_dir = repo_root / "result/ch4/exp4_2_c"

    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", default=str(default_dir), help="Dir for 4.2-C")
    parser.add_argument("--out", default=None, help="Output directory (default: same as --dir)")
    args = parser.parse_args()

    data_dir = Path(args.dir).expanduser().resolve()
    out_dir = Path(args.out).expanduser().resolve() if args.out else data_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    print("=== 4.2-C: Combined Signal ===")
    h0_path, coh_path, cmb_path = resolve_input_paths(data_dir)
    print(f"[*] baseline path       : {h0_path}")
    print(f"[*] coherence_only path : {coh_path}")
    print(f"[*] combined path       : {cmb_path}")

    if h0_path is None or coh_path is None or cmb_path is None:
        print("[!] missing required files for 4.2-C three-way analysis")
        return

    h0 = read_cycles_csv(h0_path)
    coh = read_cycles_csv(coh_path)
    cmb = read_cycles_csv(cmb_path)
    if h0.size == 0 or coh.size == 0 or cmb.size == 0:
        print("[!] empty/invalid data")
        return

    plot_threeway_hist(h0, coh, cmb, out_dir / "exp42c_threeway_hist.png")
    plot_pair_hist(h0, cmb, out_dir / "exp42c_combined_hist.png")
    plot_coh_vs_cmb_hist(coh, cmb, out_dir / "exp42c_coh_vs_cmb_hist.png")
    plot_ccdf(coh, cmb, out_dir / "exp42c_ccdf.png")
    plot_tail_bar(coh, cmb, out_dir / "exp42c_tail_bar.png")
    write_stats(h0, coh, cmb, out_dir / "stats_42c.txt")


if __name__ == "__main__":
    main()
