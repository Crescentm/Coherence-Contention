#!/usr/bin/env python3
# exp42b_analysis.py
# 分析 4.2-B（纯 DRAM 竞争）实验数据（独立脚本，不依赖 exp42bc_analysis.py）

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
plt.rcParams["font.size"] = 14
plt.rcParams["axes.titlesize"] = 16

FAST_THRESHOLD = 368

# D-range bands for RRMB template matching (Reload+Reload paper §5.3).
# Contention manifests as elevated latency in these bands; we report
# H1 vs H0 fraction ratios for each band as the primary signal metric.
DRANGE_FIXED_BANDS: list[tuple[int, int]] = [
    (392, 416),
    (416, 512),
    (392, 512),
    (416, 600),
]


def read_cycles_csv(path: Path) -> np.ndarray:
    vals = []
    with path.open(newline="") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row:
                continue
            raw = row[-1].strip()  # 支持 cycles 或 seq,cycles
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


def drange_fraction(series: np.ndarray, lo: int, hi: int) -> float:
    """Fraction of samples whose latency falls in [lo, hi)."""
    if series.size == 0:
        return float("nan")
    return float(np.sum((series >= lo) & (series < hi)) / len(series))


def find_best_drange(
    h0: np.ndarray, h1: np.ndarray,
    lo_start: int = 368, hi_end: int = 1024, step: int = 8,
) -> tuple[int, int, float]:
    """Scan [lo, hi) windows to find the band that maximises H1/H0 fraction ratio.

    Returns (best_lo, best_hi, best_ratio).  Ratio is H1_frac / H0_frac; only
    windows where H0_frac >= 0.005 are considered to avoid division by noise.
    """
    best_lo, best_hi, best_ratio = lo_start, lo_start + step, 0.0
    for lo in range(lo_start, hi_end - step, step):
        for hi in range(lo + step, min(hi_end + 1, lo + 17 * step), step):
            f1 = drange_fraction(h1, lo, hi)
            f0 = drange_fraction(h0, lo, hi)
            if f0 < 0.005:
                continue
            ratio = f1 / f0
            if ratio > best_ratio:
                best_ratio = ratio
                best_lo, best_hi = lo, hi
    return best_lo, best_hi, best_ratio


def row_buffer_hit_rate(series: np.ndarray, threshold: float = FAST_THRESHOLD) -> float:
    if series.size == 0:
        return float("nan")
    return float(np.sum(series <= threshold) / len(series))


def analyze_quantization(series: np.ndarray) -> tuple[float, float]:
    uniq = np.sort(np.unique(series))
    if uniq.size < 2:
        return float("nan"), float("nan")
    steps = np.diff(uniq)
    steps = steps[(steps >= 1) & (steps <= 50)]
    if steps.size == 0:
        return float("nan"), float("nan")
    return float(np.median(steps)), float(np.std(steps))


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


def plot_histogram(h0: np.ndarray, h1: np.ndarray, out_path: Path) -> None:
    h0_c = remove_outliers(h0)
    h1_c = remove_outliers(h1)
    if h0_c.size == 0 or h1_c.size == 0:
        return

    lo = min(np.min(h0_c), np.min(h1_c))
    hi = max(np.max(h0_c), np.max(h1_c))
    bins = np.linspace(lo, hi, 120)

    plt.figure(figsize=(9, 5))
    plt.hist(h0_c, bins=bins, alpha=0.55, color="steelblue",
             label="H0 (other_page, NOCACHE)", density=True)
    plt.hist(h1_c, bins=bins, alpha=0.55, color="darkorange",
             label="H1 (same_page, NOCACHE)", density=True)

    m0, m1 = np.mean(h0_c), np.mean(h1_c)
    s0 = np.std(h0_c)
    delta = m1 - m0
    snr = delta / s0 if s0 > 0 else float("nan")
    mw_p, _, eff = statistical_tests(h0_c, h1_c)

    plt.axvline(m0, color="steelblue", linestyle="--", linewidth=1.8, label=f"H0 mean={m0:.0f}")
    plt.axvline(m1, color="darkorange", linestyle="--", linewidth=1.8, label=f"H1 mean={m1:.0f}")
    plt.axvline(FAST_THRESHOLD, color="gray", linestyle=":", linewidth=1.2,
                label=f"Row-buf hit ≤{FAST_THRESHOLD}")

    plt.title(f"4.2-B: Pure DRAM Contention (NOCACHE)\nΔ={delta:.1f} cyc, SNR={snr:.2f}, MW p={mw_p:.2e}, r={eff:.3f}")
    plt.xlabel("Latency (cycles)")
    plt.ylabel("Density")
    plt.grid(True, linestyle=":", alpha=0.5)
    plt.legend(fontsize=11)
    plt.tight_layout()
    plt.savefig(out_path, dpi=300)
    plt.close()


def write_stats(h0: np.ndarray, h1: np.ndarray, out_path: Path) -> None:
    h0_rm = int(np.sum(h0 > 100000))
    h1_rm = int(np.sum(h1 > 100000))
    h0_c = remove_outliers(h0)
    h1_c = remove_outliers(h1)

    if h0_c.size == 0 or h1_c.size == 0:
        out_path.write_text("[4.2-B] no valid data after filtering\n")
        return

    m0, m1 = np.mean(h0_c), np.mean(h1_c)
    s0, s1 = np.std(h0_c), np.std(h1_c)
    med0, med1 = np.median(h0_c), np.median(h1_c)
    delta = m1 - m0
    snr = delta / s0 if s0 > 0 else float("nan")
    mw_p, welch_p, effect_r = statistical_tests(h0_c, h1_c)

    rbh0 = row_buffer_hit_rate(h0_c)
    rbh1 = row_buffer_hit_rate(h1_c)
    q_med, q_std = analyze_quantization(h0_c)

    # ── d-range analysis (Reload+Reload §5.3 method) ──────────────────────
    drange_lines = ["", "  --- D-range counting (Reload+Reload §5.3 method) ---"]
    for lo, hi in DRANGE_FIXED_BANDS:
        f0 = drange_fraction(h0_c, lo, hi)
        f1 = drange_fraction(h1_c, lo, hi)
        ratio = f1 / f0 if f0 > 0 else float("inf")
        drange_lines.append(
            f"  [{lo:4d},{hi:4d}) cyc:  H0={f0*100:5.2f}%  H1={f1*100:5.2f}%  ratio={ratio:.2f}x"
        )
    best_lo, best_hi, best_ratio = find_best_drange(h0_c, h1_c)
    bf0 = drange_fraction(h0_c, best_lo, best_hi)
    bf1 = drange_fraction(h1_c, best_lo, best_hi)
    drange_lines.append(
        f"  best d-range [{best_lo},{best_hi}) cyc: H0={bf0*100:.2f}%  H1={bf1*100:.2f}%  ratio={best_ratio:.2f}x"
    )
    drange_lines.append(
        "  => RRMB signal: higher ratio = stronger contention discrimination"
    )

    lines = [
        "[4.2-B Contention] Analysis",
        f"  Samples : H0={len(h0_c)} (removed {len(h0)-len(h0_c)}, incl. {h0_rm} hard-cap)"
        f" / H1={len(h1_c)} (removed {len(h1)-len(h1_c)}, incl. {h1_rm} hard-cap)",
        f"  H0 : mean={m0:.2f}, std={s0:.2f}, median={med0:.2f}",
        f"  H1 : mean={m1:.2f}, std={s1:.2f}, median={med1:.2f}",
        f"  Delta (H1-H0) : {delta:.2f} cycles",
        f"  SNR (Delta/std_H0) : {snr:.3f}",
        f"  Mann-Whitney U p-value : {mw_p:.3e}",
        f"  Welch t-test p-value   : {welch_p:.3e}",
        f"  Effect size r          : {effect_r:.4f}",
        "",
        "  --- DRAM row buffer & quantization diagnostics ---",
        f"  H0 row-buf hit rate (≤{FAST_THRESHOLD} cyc) : {rbh0*100:.2f}%",
        f"  H1 row-buf hit rate (≤{FAST_THRESHOLD} cyc) : {rbh1*100:.2f}%",
        f"  H0 RBH - H1 RBH                : {(rbh0-rbh1)*100:+.2f} pp",
        f"  DRAM quantization step (median) : {q_med:.1f} ± {q_std:.1f} cycles",
        f"  => min detectable contention Δ  : ≥{q_med:.0f} cycles (1 DRAM step)",
    ]
    lines += drange_lines
    text = "\n".join(lines) + "\n"
    print(text)
    out_path.write_text(text)


def main() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    default_dir = repo_root / "result/ch4/exp4_2_b"

    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", default=str(default_dir), help="Dir for 4.2-B (Contention)")
    parser.add_argument("--out", default=None, help="Output directory (default: same as --dir)")
    args = parser.parse_args()

    data_dir = Path(args.dir).expanduser().resolve()
    out_dir = Path(args.out).expanduser().resolve() if args.out else data_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    h0_path = data_dir / "raw_h0_cycles.csv"
    h1_path = data_dir / "raw_h1_cycles.csv"
    if not h0_path.exists() or not h1_path.exists():
        print(f"[!] missing data: {h0_path} / {h1_path}")
        return

    print("=== 4.2-B: Pure DRAM Contention ===")
    print(f"[*] Loading data from {h0_path} and {h1_path}")
    h0 = read_cycles_csv(h0_path)
    h1 = read_cycles_csv(h1_path)
    if h0.size == 0 or h1.size == 0:
        print("[!] empty/invalid data")
        return

    plot_histogram(h0, h1, out_dir / "exp42b_contention_hist.png")
    write_stats(h0, h1, out_dir / "stats_42b.txt")


if __name__ == "__main__":
    main()
