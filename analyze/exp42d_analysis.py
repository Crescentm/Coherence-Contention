#!/usr/bin/env python3
"""
exp42d_analysis.py — 实验 4.2-D：ROC 曲线与检测率评估

对齐 require/ch4.md 的 4.2-D 要求：
1) 复用 4.2-A（或 4.2-C）已有 H0/H1 样本；
2) 扫描阈值 theta（从 min(H0) 到 max(H1)）；
3) 计算 PD(theta), PFA(theta) 并绘制 ROC；
4) 报告 AUC 与最优阈值。
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
                # 跳过 header（如 cycles / seq,cycles）
                continue
    arr = np.asarray(vals, dtype=np.float64)
    if arr.size == 0:
        raise ValueError(f"no numeric samples in {path}")
    return arr


def compute_roc(h0: np.ndarray, h1: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray, float]:
    lo_core = float(np.min(h0))
    hi_core = float(np.max(h1))
    th_all = np.unique(np.concatenate([h0, h1]))
    th_core = th_all[(th_all >= lo_core) & (th_all <= hi_core)]
    if th_core.size == 0:
        th_core = np.array([lo_core, hi_core], dtype=np.float64)
    lo = np.nextafter(lo_core, -np.inf)
    hi = np.nextafter(hi_core, np.inf)
    thresholds = np.concatenate(([lo], th_core, [hi]))
    s0 = np.sort(h0)
    s1 = np.sort(h1)
    n0 = s0.size
    n1 = s1.size

    # P(T > theta) = (N - right_searchsorted(theta)) / N
    idx0 = np.searchsorted(s0, thresholds, side="right")
    idx1 = np.searchsorted(s1, thresholds, side="right")
    pfa = (n0 - idx0) / n0
    pd = (n1 - idx1) / n1

    auc = float(np.trapz(pd[::-1], pfa[::-1]))
    return thresholds, pfa, pd, auc


def best_threshold(th: np.ndarray, pfa: np.ndarray, pd: np.ndarray) -> tuple[float, float, float]:
    j = pd - pfa
    best = np.flatnonzero(j == np.max(j))
    # 若有并列，优先误报率更低，其次阈值更高（更保守）
    pick = np.lexsort((-th[best], pfa[best]))[0]
    b = best[pick]
    return float(th[b]), float(pfa[b]), float(pd[b])


def save_roc_plot(out_png: Path, pfa: np.ndarray, pd: np.ndarray, auc: float, theta: float, pfa_b: float, pd_b: float) -> None:
    fig, ax = plt.subplots(figsize=(6.2, 5.5))
    ax.plot(pfa, pd, color="#d62728", lw=2, label=f"ROC (AUC={auc:.4f})")
    ax.plot([0, 1], [0, 1], "k--", lw=1)
    ax.scatter([pfa_b], [pd_b], color="navy", zorder=5,
               label=f"theta*={theta:.0f}, PD={pd_b:.3f}, PFA={pfa_b:.4f}")
    ax.set_xlim(0.0, 1.0)
    ax.set_ylim(0.0, 1.02)
    ax.set_xlabel("PFA")
    ax.set_ylabel("PD")
    ax.set_title("Experiment 4.2-D ROC")
    ax.grid(True, ls="--", alpha=0.5)
    ax.legend(fontsize=9, loc="lower right")
    fig.tight_layout()
    fig.savefig(out_png, dpi=300)
    plt.close(fig)


def parse_args() -> argparse.Namespace:
    repo_root = Path(__file__).resolve().parents[2]
    default_data_dir = repo_root / "result/ch4/exp4_2_a"
    default_out_dir = repo_root / "result/ch4/exp4_2_d"

    ap = argparse.ArgumentParser(description="4.2-D ROC analysis")
    ap.add_argument("--data-dir", default=str(default_data_dir),
                    help="目录中需包含 raw_h0_cycles.csv / raw_h1_cycles.csv")
    ap.add_argument("--out-dir", default=str(default_out_dir),
                    help="输出目录（默认 result/ch4/exp4_2_d）")
    ap.add_argument("--max-cycles", type=float, default=None,
                    help="可选：仅保留 <= 该阈值样本（默认不过滤）")
    return ap.parse_args()


def main() -> None:
    args = parse_args()
    data_dir = Path(args.data_dir).expanduser().resolve()
    out_dir = Path(args.out_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    h0_path = data_dir / "raw_h0_cycles.csv"
    h1_path = data_dir / "raw_h1_cycles.csv"
    if not h0_path.exists() or not h1_path.exists():
        raise SystemExit(f"[4.2-D] missing H0/H1 csv under {data_dir}")

    h0 = load_cycles(h0_path)
    h1 = load_cycles(h1_path)
    if args.max_cycles is not None:
        h0 = h0[h0 <= args.max_cycles]
        h1 = h1[h1 <= args.max_cycles]
        if h0.size == 0 or h1.size == 0:
            raise SystemExit("[4.2-D] no samples left after --max-cycles filtering")

    thresholds, pfa, pd, auc = compute_roc(h0, h1)
    theta_star, pfa_star, pd_star = best_threshold(thresholds, pfa, pd)

    roc_png = out_dir / "roc_curve_42d.png"
    roc_csv = out_dir / "roc_points_42d.csv"
    roc_txt = out_dir / "stats_42d.txt"

    save_roc_plot(roc_png, pfa, pd, auc, theta_star, pfa_star, pd_star)

    with roc_csv.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["threshold", "pfa", "pd"])
        for t, fa, de in zip(thresholds, pfa, pd):
            w.writerow([f"{t:.6f}", f"{fa:.8f}", f"{de:.8f}"])

    with roc_txt.open("w") as f:
        f.write("=== Experiment 4.2-D: ROC ===\n")
        f.write(f"data_dir={data_dir}\n")
        f.write(f"h0_n={h0.size}\n")
        f.write(f"h1_n={h1.size}\n")
        f.write(f"auc={auc:.6f}\n")
        f.write(f"theta_star={theta_star:.6f}\n")
        f.write(f"pd_star={pd_star:.6f}\n")
        f.write(f"pfa_star={pfa_star:.6f}\n")

    print("=== 4.2-D ROC Analysis ===")
    print(f"data: {data_dir}")
    print(f"AUC: {auc:.6f}")
    print(f"theta*: {theta_star:.2f} cycles")
    print(f"PD(theta*): {pd_star*100:.3f}%")
    print(f"PFA(theta*): {pfa_star*100:.3f}%")
    print(f"outputs: {roc_png}, {roc_csv}, {roc_txt}")


if __name__ == "__main__":
    main()
