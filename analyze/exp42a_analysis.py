"""
exp42a_analysis.py — 实验 4.2-A：一致性信号 H0/H1 延迟分布精确分析

用法:
    python3 analyze/exp42a_analysis.py [--data-dir DIR] [--out-dir DIR]

数据来源（按优先级）:
    1. /result/ch4/exp4_2_a/  (50,000 样本新采集数据)
    2. /result/ch4/exp4_1_b/  (10,000 样本 fallback)
"""

import argparse
import csv
import os
import sys

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

plt.rcParams['font.sans-serif'] = ['SimHei', 'DejaVu Sans'] # 用来正常显示中文标签
plt.rcParams['axes.unicode_minus'] = False # 用来正常显示负号

from scipy import stats

# ─── 路径 ────────────────────────────────────────────────────────────────────
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULT_ROOT = os.path.join(REPO_ROOT, "..", "result", "ch4")

PREFERRED_DIR = os.path.join(RESULT_ROOT, "exp4_2_a")
FALLBACK_DIR  = os.path.join(RESULT_ROOT, "exp4_1_b")

# ─── CSV 加载 ─────────────────────────────────────────────────────────────────
def load_csv(path: str, max_val: float = 2000.0) -> np.ndarray:
    data = []
    with open(path, newline="") as f:
        reader = csv.reader(f)
        next(reader, None)  # skip header
        for row in reader:
            if not row:
                continue
            try:
                v = float(row[0])
                if v <= max_val:
                    data.append(v)
            except ValueError:
                pass
    return np.array(data, dtype=float)


# ─── 统计量 ──────────────────────────────────────────────────────────────────
def print_stats(label: str, data: np.ndarray) -> dict:
    n    = len(data)
    mean = float(np.mean(data))
    med  = float(np.median(data))
    std  = float(np.std(data))
    p5   = float(np.percentile(data, 5))
    p95  = float(np.percentile(data, 95))
    print(f"  [{label}]  n={n}  mean={mean:.1f}  median={med:.0f}  std={std:.1f}"
          f"  P5={p5:.0f}  P95={p95:.0f}")
    return dict(n=n, mean=mean, median=med, std=std, p5=p5, p95=p95)


# ─── 分布重叠估计 ─────────────────────────────────────────────────────────────
def overlap_fraction(h0: np.ndarray, h1: np.ndarray, n_bins: int = 500) -> float:
    """
    直方图重叠系数 (Bhattacharyya 系数近似):
        OVL = sum( min(P_H0(k), P_H1(k)) ) over all bins
    """
    all_min = min(h0.min(), h1.min())
    all_max = max(h0.max(), h1.max())
    bins = np.linspace(all_min, all_max, n_bins + 1)

    cnt0, _ = np.histogram(h0, bins=bins, density=True)
    cnt1, _ = np.histogram(h1, bins=bins, density=True)

    bin_w = bins[1] - bins[0]
    ovl = float(np.sum(np.minimum(cnt0, cnt1)) * bin_w)
    return ovl


# ─── ROC + AUC ───────────────────────────────────────────────────────────────
def compute_roc(h0: np.ndarray, h1: np.ndarray):
    thresholds = np.unique(np.concatenate([h0, h1]))
    fa_list, pd_list = [], []
    n0, n1 = len(h0), len(h1)
    for th in thresholds:
        fa_list.append(np.sum(h0 > th) / n0)
        pd_list.append(np.sum(h1 > th) / n1)
    fa = np.array(fa_list)
    pd = np.array(pd_list)
    auc = float(np.trapz(pd[::-1], fa[::-1]))
    best_idx = int(np.argmax(pd - fa))
    return fa, pd, auc, thresholds[best_idx], fa[best_idx], pd[best_idx]


# ─── 绘图 ────────────────────────────────────────────────────────────────────
def plot_histogram(h0: np.ndarray, h1: np.ndarray,
                   out_path: str, theta_opt: float):
    fig, ax = plt.subplots(figsize=(8, 4.5))

    # KDE 曲线
    x_min = max(0, min(h0.min(), h1.min()) - 50)
    x_max = min(2000, max(h0.max(), h1.max()) + 50)
    xs = np.linspace(x_min, x_max, 800)

    kde0 = stats.gaussian_kde(h0, bw_method=0.08)
    kde1 = stats.gaussian_kde(h1, bw_method=0.08)

    ax.fill_between(xs, kde0(xs), alpha=0.35, color="#1f77b4", label="H0 – 无逐出 (baseline)")
    ax.fill_between(xs, kde1(xs), alpha=0.35, color="#d62728", label="H1 – 跨域一致性逐出 (eviction)")
    ax.plot(xs, kde0(xs), color="#1f77b4", lw=1.5)
    ax.plot(xs, kde1(xs), color="#d62728", lw=1.5)

    # 最优阈值线
    ax.axvline(theta_opt, color="black", lw=1.2, ls="--",
               label=f"最优阈值 θ* = {theta_opt:.0f} cycles")

    ax.set_xlabel("延迟 (TSC cycles)", fontsize=12)
    ax.set_ylabel("密度", fontsize=12)
    ax.set_title("实验 4.2-A：一致性信号 H0/H1 延迟分布", fontsize=13)
    ax.legend(fontsize=10)
    ax.set_xlim(x_min, x_max)
    ax.grid(True, ls="--", alpha=0.5)

    fig.tight_layout()
    fig.savefig(out_path, dpi=300)
    plt.close(fig)
    print(f"  [图] {out_path}")


def plot_roc(fa: np.ndarray, pd: np.ndarray, auc: float,
             theta: float, fa_opt: float, pd_opt: float,
             out_path: str):
    fig, ax = plt.subplots(figsize=(5.5, 5))
    ax.plot(fa, pd, color="#d62728", lw=2, label=f"ROC (AUC = {auc:.4f})")
    ax.plot([0, 1], [0, 1], "k--", lw=1)
    ax.scatter([fa_opt], [pd_opt], color="navy", zorder=5,
               label=f"θ*={theta:.0f}: PD={pd_opt:.3f}, PFA={fa_opt:.4f}")
    ax.set_xlabel("误报率 PFA", fontsize=12)
    ax.set_ylabel("检测率 PD", fontsize=12)
    ax.set_title("实验 4.2-D：ROC 曲线", fontsize=13)
    ax.legend(fontsize=9)
    ax.grid(True, ls="--", alpha=0.5)
    fig.tight_layout()
    fig.savefig(out_path, dpi=300)
    plt.close(fig)
    print(f"  [图] {out_path}")


# ─── 信道容量 ─────────────────────────────────────────────────────────────────
def bsc_capacity(pd: float, pfa: float) -> float:
    p_e = ((1 - pd) + pfa) / 2.0
    if p_e <= 0 or p_e >= 1:
        return 0.0
    def h(p):
        return -p * np.log2(p) - (1 - p) * np.log2(1 - p)
    return float(1.0 - h(p_e))


# ─── 主程序 ──────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", default="", help="包含 raw_h0_cycles.csv / raw_h1_cycles.csv 的目录")
    ap.add_argument("--out-dir",  default="", help="图片和统计文件输出目录（默认与数据同目录）")
    args = ap.parse_args()

    # 确定数据目录
    if args.data_dir:
        data_dir = args.data_dir
    elif os.path.isdir(PREFERRED_DIR) and \
         os.path.exists(os.path.join(PREFERRED_DIR, "raw_h0_cycles.csv")):
        data_dir = PREFERRED_DIR
        print(f"[使用 50k 数据] {data_dir}")
    elif os.path.isdir(FALLBACK_DIR) and \
         os.path.exists(os.path.join(FALLBACK_DIR, "raw_h0_cycles.csv")):
        data_dir = FALLBACK_DIR
        print(f"[回退至 10k 数据] {data_dir}")
    else:
        sys.exit("错误：找不到 raw_h0_cycles.csv。请先运行 run_42a.py 或确认路径。")

    out_dir = args.out_dir if args.out_dir else data_dir
    os.makedirs(out_dir, exist_ok=True)

    h0 = load_csv(os.path.join(data_dir, "raw_h0_cycles.csv"))
    h1 = load_csv(os.path.join(data_dir, "raw_h1_cycles.csv"))

    print(f"\n=== 实验 4.2-A：一致性信号延迟分布分析 ============================")
    print(f"数据目录: {data_dir}")
    s0 = print_stats("H0 baseline", h0)
    s1 = print_stats("H1 eviction", h1)

    delta_median = s1["median"] - s0["median"]
    delta_mean   = s1["mean"]   - s0["mean"]
    ovl          = overlap_fraction(h0, h1)
    snr          = abs(s1["mean"] - s0["mean"]) / \
                   np.sqrt((s0["std"] ** 2 + s1["std"] ** 2) / 2.0)

    print(f"\n  Δ_coh (中位数差): {delta_median:.1f} cycles")
    print(f"  Δ_coh (均值差):   {delta_mean:.1f} cycles")
    print(f"  分布重叠系数 OVL: {ovl:.4f}")
    print(f"  SNR (Cohen's d):  {snr:.3f}")

    fa, pd, auc, theta_opt, fa_opt, pd_opt = compute_roc(h0, h1)
    cap = bsc_capacity(pd_opt, fa_opt)

    print(f"\n=== ROC ====")
    print(f"  AUC:              {auc:.4f}")
    print(f"  最优阈值 θ*:     {theta_opt:.0f} cycles")
    print(f"  检测率 PD:        {pd_opt*100:.2f}%")
    print(f"  误报率 PFA:       {fa_opt*100:.3f}%")
    print(f"  信道容量 (BSC):   {cap:.4f} bits/probe")

    # ─── 生成图表 ──────────────────────────────────────────────────────────
    plot_histogram(h0, h1,
                   os.path.join(out_dir, "exp42a_hist_kde.png"),
                   theta_opt)
    plot_roc(fa, pd, auc, theta_opt, fa_opt, pd_opt,
             os.path.join(out_dir, "exp42a_roc.png"))

    # ─── TikZ 坐标输出 ─────────────────────────────────────────────────────
    print("\n=== TikZ 坐标 (ROC, 50 points) ===")
    idx = np.linspace(0, len(fa) - 1, 50, dtype=int)
    for i in idx:
        print(f"  ({fa[i]:.4f},{pd[i]:.4f})")

    # ─── 统计文件 ──────────────────────────────────────────────────────────
    stats_path = os.path.join(out_dir, "stats_42a.txt")
    with open(stats_path, "w") as f:
        f.write("=== Experiment 4.2-A: Coherence Signal H0/H1 ===\n\n")
        for label, s in [("H0 baseline", s0), ("H1 eviction", s1)]:
            f.write(f"[{label}]\n")
            for k, v in s.items():
                f.write(f"  {k}: {v:.2f}\n")
            f.write("\n")
        f.write(f"Delta_coh_median: {delta_median:.1f} cycles\n")
        f.write(f"Delta_coh_mean:   {delta_mean:.1f} cycles\n")
        f.write(f"Overlap (OVL):    {ovl:.4f}\n")
        f.write(f"SNR:              {snr:.3f}\n")
        f.write(f"AUC:              {auc:.4f}\n")
        f.write(f"Theta_opt:        {theta_opt:.0f}\n")
        f.write(f"PD_opt:           {pd_opt:.4f}\n")
        f.write(f"PFA_opt:          {fa_opt:.4f}\n")
        f.write(f"BSC_capacity:     {cap:.4f} bits/probe\n")
    print(f"\n  [统计] {stats_path}")


if __name__ == "__main__":
    main()
