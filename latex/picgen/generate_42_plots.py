#!/usr/bin/env python3
"""Generate Chapter 4.2 plots for the thesis."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib import font_manager
import numpy as np


def configure_matplotlib() -> None:
    for font_path in [
        "/usr/local/share/fonts/LXGWNeoXiHei.ttf",
        "/usr/local/share/fonts/wqy-zenhei.ttf",
        "/usr/local/share/fonts/NotoSansCJKsc-VF.otf",
    ]:
        try:
            font_manager.fontManager.addfont(font_path)
        except Exception:
            pass
    plt.rcParams.update(
        {
            "font.sans-serif": [
                "LXGW Neo XiHei",
                "Noto Sans CJK SC",
                "WenQuanYi Zen Hei",
                "SimHei",
                "DejaVu Sans",
                "sans-serif",
            ],
            "axes.unicode_minus": False,
            "figure.dpi": 120,
            "savefig.dpi": 300,
            "font.size": 12,
            "axes.titlesize": 14,
            "axes.labelsize": 12,
            "legend.fontsize": 10,
            "xtick.labelsize": 10,
            "ytick.labelsize": 10,
        }
    )


def load_cycles(path: Path) -> np.ndarray:
    values: list[float] = []
    with path.open(newline="") as handle:
        reader = csv.reader(handle)
        for row in reader:
            if not row:
                continue
            try:
                values.append(float(row[-1]))
            except ValueError:
                continue
    return np.asarray(values, dtype=np.float64)


def load_matrix(path: Path) -> np.ndarray:
    rows: list[list[float]] = []
    with path.open(newline="") as handle:
        reader = csv.reader(handle)
        header = next(reader, None)
        for row in reader:
            if not row:
                continue
            try:
                rows.append([float(v) for v in row[1:]])
            except ValueError:
                continue
    if not rows:
        raise ValueError(f"empty matrix: {path}")
    return np.asarray(rows, dtype=np.float64)


def trim_percentile(values: np.ndarray, lower: float = 0.5, upper: float = 99.5) -> np.ndarray:
    if values.size == 0:
        return values
    lo = np.percentile(values, lower)
    hi = np.percentile(values, upper)
    return values[(values >= lo) & (values <= hi)]


def save_figure(fig: plt.Figure, path: Path, tight: bool = True) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if tight:
        fig.tight_layout()
    fig.savefig(path, bbox_inches="tight")
    plt.close(fig)


def plot_coherence_42a(result_dir: Path, out_path: Path) -> None:
    h0 = load_cycles(result_dir / "raw_h0_cycles.csv")
    h1 = load_cycles(result_dir / "raw_h1_cycles.csv")
    h0 = h0[h0 <= 2000]
    h1 = h1[h1 <= 2000]

    lo = min(np.percentile(h0, 0.5), np.percentile(h1, 0.5))
    hi = max(np.percentile(h0, 99.5), np.percentile(h1, 99.5))
    bins = np.linspace(lo, hi, 90)

    fig, ax = plt.subplots(figsize=(8.8, 4.8))
    ax.hist(h0, bins=bins, density=True, alpha=0.55, color="#4C78A8", label="H0：控制页基线")
    ax.hist(h1, bins=bins, density=True, alpha=0.45, color="#E45756", label="H1：跨域一致性逐出")

    mean_h0 = float(np.mean(h0))
    mean_h1 = float(np.mean(h1))
    ax.axvline(mean_h0, color="#2F5D8A", linestyle="--", linewidth=1.6)
    ax.axvline(mean_h1, color="#B33A39", linestyle="--", linewidth=1.6)
    ax.text(
        0.98,
        0.96,
        f"H0 均值：{mean_h0:.1f} cycles\nH1 均值：{mean_h1:.1f} cycles\n差值：{mean_h1 - mean_h0:.1f} cycles",
        transform=ax.transAxes,
        ha="right",
        va="top",
        bbox={"boxstyle": "round,pad=0.35", "facecolor": "white", "edgecolor": "#BBBBBB"},
    )

    ax.set_title("跨域一致性逐出延迟分布")
    ax.set_xlabel("延迟（cycles）")
    ax.set_ylabel("密度")
    ax.grid(True, linestyle=":", alpha=0.45)
    ax.legend(loc="upper left")
    save_figure(fig, out_path)


def plot_heatmap_42aplus(result_dir: Path, out_path: Path) -> None:
    candidate_dirs = [
        result_dir.parent.parent / "amd_ciphertext_20260324_181542",
        result_dir.parent.parent / "amd_ciphertext_20260324_175523",
        result_dir.parent.parent / "amd_ciphertext_20260324_175433",
    ]
    matrix_dir = None
    same_path = None
    other_path = None
    for cand in candidate_dirs:
        s = cand / "same_page_matrix.csv"
        o = cand / "other_page_matrix.csv"
        if s.exists() and o.exists():
            matrix_dir = cand
            same_path = s
            other_path = o
            break
    if matrix_dir is None or same_path is None or other_path is None:
        raise FileNotFoundError("cannot locate same_page_matrix.csv / other_page_matrix.csv")

    same = load_matrix(same_path)
    other = load_matrix(other_path)
    if same.shape != (64, 64) or other.shape != (64, 64):
        raise ValueError(f"expected 64x64 matrices, got {same.shape} and {other.shape}")

    valid = np.concatenate([same.ravel(), other.ravel()])
    vmin = float(np.percentile(valid, 1))
    vmax = float(np.percentile(valid, 99))

    fig = plt.figure(figsize=(13.0, 5.8))
    gs = fig.add_gridspec(1, 3, width_ratios=[1, 1, 0.04], wspace=0.22)
    axes = [fig.add_subplot(gs[0, 0]), fig.add_subplot(gs[0, 1])]
    cax = fig.add_subplot(gs[0, 2])
    for ax, mat, title in [
        (axes[0], same, "同页 64×64 延迟矩阵"),
        (axes[1], other, "跨页 64×64 延迟矩阵"),
    ]:
        im = ax.imshow(mat, cmap="YlOrRd", aspect="equal", vmin=vmin, vmax=vmax)
        ax.set_title(title)
        ax.set_xlabel("宿主探测行号")
        ax.set_ylabel("来宾 victim line")
        ax.set_xticks(np.arange(0, 64, 8))
        ax.set_yticks(np.arange(0, 64, 8))
        ax.axhline(31.5, color="#222222", linewidth=1.0)
        ax.axvline(31.5, color="#222222", linewidth=1.0)
        for line in range(8, 64, 8):
            ax.axhline(line - 0.5, color="white", linewidth=0.45, alpha=0.35)
            ax.axvline(line - 0.5, color="white", linewidth=0.45, alpha=0.35)

    cbar = fig.colorbar(im, cax=cax)
    cbar.set_label("平均延迟（cycles）")
    fig.suptitle("同页与跨页 64×64 延迟矩阵及 DRAM Interleaving 结构", y=0.98)
    save_figure(fig, out_path, tight=False)


def plot_contention_42b(result_dir: Path, out_path: Path) -> None:
    h0 = trim_percentile(load_cycles(result_dir / "raw_h0_cycles.csv"))
    h1 = trim_percentile(load_cycles(result_dir / "raw_h1_cycles.csv"))

    lo = min(np.min(h0), np.min(h1))
    hi = max(np.max(h0), np.max(h1))
    bins = np.linspace(lo, hi, 95)

    fig, ax = plt.subplots(figsize=(8.8, 4.8))
    ax.hist(h0, bins=bins, density=True, alpha=0.55, color="#4C78A8", label=r"$H_0$：控制页，无竞争")
    ax.hist(h1, bins=bins, density=True, alpha=0.45, color="#F58518", label=r"$H_1$：NOCACHE 竞争")

    mean_h0 = float(np.mean(h0))
    mean_h1 = float(np.mean(h1))
    ax.axvline(mean_h0, color="#2F5D8A", linestyle="--", linewidth=1.6)
    ax.axvline(mean_h1, color="#B75B10", linestyle="--", linewidth=1.6)
    ax.text(
        0.98,
        0.96,
        f"H0 均值：{mean_h0:.1f} cycles\nH1 均值：{mean_h1:.1f} cycles\n差值：{mean_h1 - mean_h0:.1f} cycles",
        transform=ax.transAxes,
        ha="right",
        va="top",
        bbox={"boxstyle": "round,pad=0.35", "facecolor": "white", "edgecolor": "#BBBBBB"},
    )

    ax.set_title("纯 DRAM 竞争信号延迟分布")
    ax.set_xlabel("延迟（cycles）")
    ax.set_ylabel("密度")
    ax.grid(True, linestyle=":", alpha=0.45)
    ax.legend(loc="upper left", fontsize=9)
    save_figure(fig, out_path)


def tail_ratio(values: np.ndarray, threshold: float) -> float:
    return float(np.mean(values > threshold))


def plot_threeway_42c(result_dir: Path, out_path: Path) -> None:
    h0 = trim_percentile(load_cycles(result_dir / "raw_h0_cycles.csv"))
    coh = trim_percentile(load_cycles(result_dir / "raw_h1_coherence_cycles.csv"))
    cmb = trim_percentile(load_cycles(result_dir / "raw_h1_cycles.csv"))

    lo = min(np.min(h0), np.min(coh), np.min(cmb))
    hi = max(np.max(h0), np.max(coh), np.max(cmb))
    bins = np.linspace(lo, hi, 105)

    fig, ax = plt.subplots(figsize=(9.2, 5.1))
    ax.hist(h0, bins=bins, density=True, alpha=0.52, color="#4C78A8", label=r"$H_0$：热缓存基线")
    ax.hist(coh, bins=bins, density=True, alpha=0.42, color="#54A24B", label=r"$H_1^{\mathrm{coh}}$")
    ax.hist(cmb, bins=bins, density=True, alpha=0.40, color="#E45756", label=r"$H_1^{\mathrm{cmb}}$")

    ax.axvline(np.mean(h0), color="#2F5D8A", linestyle="--", linewidth=1.4)
    ax.axvline(np.mean(coh), color="#3F7F3B", linestyle="--", linewidth=1.4)
    ax.axvline(np.mean(cmb), color="#B33A39", linestyle="--", linewidth=1.4)
    ax.axvline(700, color="#555555", linestyle=":", linewidth=1.2)

    ax.text(
        0.98,
        0.96,
        r"$P(T>700\mid H_1^{\mathrm{coh}})$"
        f" = {tail_ratio(coh, 700) * 100:.2f}%\n"
        r"$P(T>700\mid H_1^{\mathrm{cmb}})$"
        f" = {tail_ratio(cmb, 700) * 100:.2f}%",
        transform=ax.transAxes,
        ha="right",
        va="top",
        bbox={"boxstyle": "round,pad=0.35", "facecolor": "white", "edgecolor": "#BBBBBB"},
    )

    ax.set_title("基线、仅一致性与叠加信号对比")
    ax.set_xlabel("延迟（cycles）")
    ax.set_ylabel("密度")
    ax.grid(True, linestyle=":", alpha=0.45)
    ax.legend(loc="upper left")
    save_figure(fig, out_path)


def plot_capacity_42e(result_dir: Path, out_path: Path) -> None:
    rates: list[float] = []
    hist_tp: list[float] = []
    gauss_tp: list[float] = []
    bac_tp: list[float] = []

    with (result_dir / "capacity_42e_vs_probe_rate.csv").open(newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            rates.append(float(row["probe_rate_hz"]) / 1000.0)
            hist_tp.append(float(row["throughput_hist_bps"]) / 1000.0)
            gauss_tp.append(float(row["throughput_gauss_bps"]) / 1000.0)
            bac_tp.append(float(row["throughput_bac_bps"]) / 1000.0)

    fig, axes = plt.subplots(3, 1, figsize=(7.6, 7.8), sharex=True, sharey=True)
    series = [
        (axes[0], hist_tp, "直方图互信息", "#4C78A8", "o"),
        (axes[1], gauss_tp, "高斯近似", "#72B7B2", "s"),
        (axes[2], bac_tp, "BAC 容量", "#E45756", "^"),
    ]
    y_max = max(max(hist_tp), max(gauss_tp), max(bac_tp)) * 1.03
    for ax, values, title, color, marker in series:
        ax.plot(rates, values, marker=marker, linewidth=2, color=color)
        ax.set_title(title, fontsize=12)
        ax.set_ylim(0, y_max)
        ax.grid(True, linestyle=":", alpha=0.45)
        ax.set_ylabel("理论吞吐（kb/s)")
        ax.annotate(
            f"{values[-1]:.1f}",
            xy=(rates[-1], values[-1]),
            xytext=(6, 0),
            textcoords="offset points",
            va="center",
            fontsize=9,
            color=color,
        )

    axes[-1].set_xlabel("探测速率（kHz）")
    fig.suptitle("不同探测频率下的物理信道容量线性外推结果", y=0.995)
    fig.tight_layout(rect=(0, 0, 1, 0.98))
    fig.savefig(out_path, bbox_inches="tight")
    plt.close(fig)


def parse_args() -> argparse.Namespace:
    repo_root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description="Generate Chapter 4.2 plots.")
    parser.add_argument("--repo-root", default=str(repo_root))
    parser.add_argument("--out-dir", default="")
    return parser.parse_args()


def main() -> None:
    configure_matplotlib()
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()
    out_dir = Path(args.out_dir).resolve() if args.out_dir else repo_root / "latex" / "pic"
    out_dir.mkdir(parents=True, exist_ok=True)

    plot_coherence_42a(repo_root / "result" / "ch4" / "exp4_2_a", out_dir / "coherence_42a.png")
    plot_heatmap_42aplus(repo_root / "result" / "ch4" / "exp4_2_aplus", out_dir / "heatmap_42aplus.png")
    plot_contention_42b(repo_root / "result" / "ch4" / "exp4_2_b", out_dir / "contention_42b.png")
    plot_threeway_42c(repo_root / "result" / "ch4" / "exp4_2_c", out_dir / "threeway_42c.png")
    plot_capacity_42e(repo_root / "result" / "ch4" / "exp4_2_e", out_dir / "capacity_42e.png")


if __name__ == "__main__":
    main()
