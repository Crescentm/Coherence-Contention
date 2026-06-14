#!/usr/bin/env python3
"""
exp42e_analysis.py — 实验 4.2-E：信道容量估计（可选）

对齐 require/ch4.md 的 4.2-E 思路：
1) 用 H0/H1 延迟分布离散化计算互信息；
2) 给出二元阈值检测信道（BSC/BAC 视角）容量估计；
3) 输出 bits/probe，并给出可选的 probe 频率吞吐曲线。
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np

plt.rcParams["font.sans-serif"] = ["SimHei", "DejaVu Sans"]
plt.rcParams["axes.unicode_minus"] = False


def load_cycles(path: Path) -> np.ndarray:
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
    arr = np.asarray(vals, dtype=np.float64)
    if arr.size == 0:
        raise ValueError(f"no numeric samples in {path}")
    return arr


def h2(p: np.ndarray | float) -> np.ndarray | float:
    p_arr = np.asarray(p, dtype=np.float64)
    out = np.zeros_like(p_arr)
    m = (p_arr > 0.0) & (p_arr < 1.0)
    out[m] = -(p_arr[m] * np.log2(p_arr[m]) + (1.0 - p_arr[m]) * np.log2(1.0 - p_arr[m]))
    return out if isinstance(p, np.ndarray) else float(out)


def roc_threshold(h0: np.ndarray, h1: np.ndarray) -> tuple[float, float, float]:
    lo = float(np.min(h0))
    hi = float(np.max(h1))
    th_all = np.unique(np.concatenate([h0, h1]))
    th = th_all[(th_all >= lo) & (th_all <= hi)]
    if th.size == 0:
        th = np.array([lo, hi], dtype=np.float64)
    s0 = np.sort(h0)
    s1 = np.sort(h1)
    pfa = (s0.size - np.searchsorted(s0, th, side="right")) / s0.size
    pd = (s1.size - np.searchsorted(s1, th, side="right")) / s1.size
    j = pd - pfa
    idx = int(np.argmax(j))
    return float(th[idx]), float(pd[idx]), float(pfa[idx])


def mi_histogram(h0: np.ndarray, h1: np.ndarray, bins: int) -> float:
    lo = float(min(h0.min(), h1.min()))
    hi = float(max(h0.max(), h1.max()))
    if hi <= lo:
        return 0.0

    cnt0, edges = np.histogram(h0, bins=bins, range=(lo, hi), density=False)
    cnt1, _ = np.histogram(h1, bins=bins, range=(lo, hi), density=False)
    p0 = cnt0 / np.sum(cnt0)
    p1 = cnt1 / np.sum(cnt1)
    py = 0.5 * (p0 + p1)

    mi0 = np.zeros_like(p0, dtype=np.float64)
    m0 = (p0 > 0) & (py > 0)
    mi0[m0] = p0[m0] * np.log2(p0[m0] / py[m0])
    mi1 = np.zeros_like(p1, dtype=np.float64)
    m1 = (p1 > 0) & (py > 0)
    mi1[m1] = p1[m1] * np.log2(p1[m1] / py[m1])
    return float(0.5 * np.sum(mi0) + 0.5 * np.sum(mi1))


def mi_gaussian_mc(h0: np.ndarray, h1: np.ndarray, n_samples: int, seed: int) -> float:
    mu0, s0 = float(np.mean(h0)), float(np.std(h0))
    mu1, s1 = float(np.mean(h1)), float(np.std(h1))
    if s0 <= 0 or s1 <= 0:
        return 0.0

    rng = np.random.default_rng(seed)
    x = rng.integers(0, 2, size=n_samples, dtype=np.int8)
    y = np.empty(n_samples, dtype=np.float64)
    y[x == 0] = rng.normal(mu0, s0, np.sum(x == 0))
    y[x == 1] = rng.normal(mu1, s1, np.sum(x == 1))

    def norm_pdf(arr: np.ndarray, mu: float, sigma: float) -> np.ndarray:
        z = (arr - mu) / sigma
        return np.exp(-0.5 * z * z) / (sigma * np.sqrt(2.0 * np.pi))

    p_y_x0 = norm_pdf(y, mu0, s0)
    p_y_x1 = norm_pdf(y, mu1, s1)
    p_y = 0.5 * (p_y_x0 + p_y_x1)
    ratio = np.where(x == 0, p_y_x0, p_y_x1) / np.maximum(p_y, 1e-300)
    return float(np.mean(np.log2(np.maximum(ratio, 1e-300))))


def bac_capacity(pd: float, pfa: float) -> float:
    q = np.linspace(0.0, 1.0, 20001)
    py1 = q * pd + (1.0 - q) * pfa
    ixy = h2(py1) - q * h2(pd) - (1.0 - q) * h2(pfa)
    return float(np.max(ixy))


def parse_rates(s: str) -> list[float]:
    out = []
    for p in s.split(","):
        p = p.strip()
        if not p:
            continue
        out.append(float(p))
    return out


def parse_args() -> argparse.Namespace:
    repo_root = Path(__file__).resolve().parents[2]
    default_data_dir = repo_root / "result/ch4/exp4_2_a"
    default_out_dir = repo_root / "result/ch4/exp4_2_e"
    default_rates = "10000,50000,100000,200000,500000,1000000"

    ap = argparse.ArgumentParser(description="4.2-E channel-capacity estimation")
    ap.add_argument("--data-dir", default=str(default_data_dir),
                    help="目录中需包含 raw_h0_cycles.csv / raw_h1_cycles.csv")
    ap.add_argument("--out-dir", default=str(default_out_dir),
                    help="输出目录（默认 result/ch4/exp4_2_e）")
    ap.add_argument("--bins", type=int, default=128,
                    help="离散化直方图桶数")
    ap.add_argument("--max-cycles", type=float, default=None,
                    help="可选：仅保留 <= 该阈值样本")
    ap.add_argument("--mc-samples", type=int, default=200000,
                    help="高斯信道 MI Monte-Carlo 样本数")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--probe-rates", default=default_rates,
                    help="可选吞吐曲线的 probe 频率列表(Hz)，逗号分隔")
    return ap.parse_args()


def main() -> None:
    args = parse_args()
    data_dir = Path(args.data_dir).expanduser().resolve()
    out_dir = Path(args.out_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    h0_path = data_dir / "raw_h0_cycles.csv"
    h1_path = data_dir / "raw_h1_cycles.csv"
    if not h0_path.exists() or not h1_path.exists():
        raise SystemExit(f"[4.2-E] missing H0/H1 csv under {data_dir}")

    h0 = load_cycles(h0_path)
    h1 = load_cycles(h1_path)
    if args.max_cycles is not None:
        h0 = h0[h0 <= args.max_cycles]
        h1 = h1[h1 <= args.max_cycles]
        if h0.size == 0 or h1.size == 0:
            raise SystemExit("[4.2-E] no samples left after --max-cycles filtering")

    theta, pd, pfa = roc_threshold(h0, h1)
    pe = ((1.0 - pd) + pfa) / 2.0
    c_bsc_approx = float(1.0 - h2(pe))
    i_bac_equal = float(h2(0.5 * (pd + pfa)) - 0.5 * h2(pd) - 0.5 * h2(pfa))
    c_bac = bac_capacity(pd, pfa)

    i_hist = mi_histogram(h0, h1, args.bins)
    i_gauss = mi_gaussian_mc(h0, h1, args.mc_samples, args.seed)

    stats_txt = out_dir / "stats_42e.txt"
    with stats_txt.open("w") as f:
        f.write("=== Experiment 4.2-E: Channel Capacity ===\n")
        f.write(f"data_dir={data_dir}\n")
        f.write(f"h0_n={h0.size}\n")
        f.write(f"h1_n={h1.size}\n")
        f.write(f"theta_star={theta:.6f}\n")
        f.write(f"pd_star={pd:.6f}\n")
        f.write(f"pfa_star={pfa:.6f}\n")
        f.write(f"bsc_pe={pe:.6f}\n")
        f.write(f"bsc_capacity_approx={c_bsc_approx:.6f}\n")
        f.write(f"bac_mutual_info_equal_prior={i_bac_equal:.6f}\n")
        f.write(f"bac_capacity={c_bac:.6f}\n")
        f.write(f"hist_mutual_info_bins{args.bins}={i_hist:.6f}\n")
        f.write(f"gaussian_mutual_info_mc={i_gauss:.6f}\n")

    rates = parse_rates(args.probe_rates)
    if rates:
        rates_arr = np.asarray(rates, dtype=np.float64)
        curve_csv = out_dir / "capacity_42e_vs_probe_rate.csv"
        curve_png = out_dir / "capacity_42e_vs_probe_rate.png"
        with curve_csv.open("w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["probe_rate_hz", "throughput_hist_bps", "throughput_gauss_bps", "throughput_bac_bps"])
            for r in rates_arr:
                w.writerow([f"{r:.2f}", f"{i_hist*r:.6f}", f"{i_gauss*r:.6f}", f"{c_bac*r:.6f}"])

        fig, ax = plt.subplots(figsize=(6.6, 4.8))
        ax.plot(rates_arr, i_hist * rates_arr, marker="o", label=f"Histogram MI ({i_hist:.3f} bits/probe)")
        ax.plot(rates_arr, i_gauss * rates_arr, marker="s", label=f"Gaussian MI ({i_gauss:.3f} bits/probe)")
        ax.plot(rates_arr, c_bac * rates_arr, marker="^", label=f"BAC Capacity ({c_bac:.3f} bits/probe)")
        ax.set_xlabel("Probe Rate (Hz)")
        ax.set_ylabel("Estimated Throughput (bits/s)")
        ax.set_title("Experiment 4.2-E Capacity vs Probe Rate")
        ax.grid(True, ls="--", alpha=0.5)
        ax.legend(fontsize=9)
        fig.tight_layout()
        fig.savefig(curve_png, dpi=300)
        plt.close(fig)

    print("=== 4.2-E Capacity Analysis ===")
    print(f"data: {data_dir}")
    print(f"theta*: {theta:.2f} cycles, PD={pd:.4f}, PFA={pfa:.4f}")
    print(f"BSC approx capacity: {c_bsc_approx:.6f} bits/probe")
    print(f"BAC equal-prior MI:  {i_bac_equal:.6f} bits/probe")
    print(f"BAC capacity:        {c_bac:.6f} bits/probe")
    print(f"Histogram MI:        {i_hist:.6f} bits/probe")
    print(f"Gaussian MI (MC):    {i_gauss:.6f} bits/probe")
    print(f"stats: {stats_txt}")


if __name__ == "__main__":
    main()
