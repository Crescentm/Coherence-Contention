#!/usr/bin/env python3
"""Generate the Chapter 4.1-B delay histogram."""

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


def parse_args() -> argparse.Namespace:
    repo_root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description="Generate the Chapter 4.1-B histogram.")
    parser.add_argument("--repo-root", default=str(repo_root))
    parser.add_argument(
        "--result-dir",
        default="",
        help="Result directory that contains raw_h0_cycles.csv and raw_h1_cycles.csv.",
    )
    parser.add_argument(
        "--out-dir",
        default="",
        help="Output directory for the generated figure.",
    )
    parser.add_argument(
        "--out-name",
        default="delay_hist_41b.png",
        help="Output file name.",
    )
    return parser.parse_args()


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


def trim_percentile(values: np.ndarray, lower: float = 0.5, upper: float = 99.5) -> np.ndarray:
    if values.size == 0:
        return values
    lo = np.percentile(values, lower)
    hi = np.percentile(values, upper)
    return values[(values >= lo) & (values <= hi)]


def save_figure(fig: plt.Figure, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    fig.savefig(path, bbox_inches="tight")
    plt.close(fig)


def plot_delay_histogram(result_dir: Path, out_path: Path) -> None:
    h0 = trim_percentile(load_cycles(result_dir / "raw_h0_cycles.csv"))
    h1 = trim_percentile(load_cycles(result_dir / "raw_h1_cycles.csv"))

    if h0.size == 0 or h1.size == 0:
        raise ValueError("empty delay sample set")

    lo = min(np.min(h0), np.min(h1))
    hi = max(np.max(h0), np.max(h1))
    bins = np.linspace(lo, hi, 90)

    fig, ax = plt.subplots(figsize=(8.8, 4.8))
    ax.hist(h0, bins=bins, density=True, alpha=0.55, color="#4C78A8", label="H0：无逐出")
    ax.hist(h1, bins=bins, density=True, alpha=0.45, color="#E45756", label="H1：跨域一致性逐出")

    mean_h0 = float(np.mean(h0))
    mean_h1 = float(np.mean(h1))
    median_h0 = float(np.median(h0))
    median_h1 = float(np.median(h1))

    ax.axvline(mean_h0, color="#2F5D8A", linestyle="--", linewidth=1.5)
    ax.axvline(mean_h1, color="#B33A39", linestyle="--", linewidth=1.5)
    ax.axvline(median_h0, color="#2F5D8A", linestyle=":", linewidth=1.2, alpha=0.85)
    ax.axvline(median_h1, color="#B33A39", linestyle=":", linewidth=1.2, alpha=0.85)

    ax.text(
        0.98,
        0.96,
        f"H0 均值：{mean_h0:.2f} cycles\n"
        f"H1 均值：{mean_h1:.2f} cycles\n"
        f"均值差：{mean_h1 - mean_h0:.2f} cycles\n"
        f"H0 中位数：{median_h0:.0f} cycles\n"
        f"H1 中位数：{median_h1:.0f} cycles",
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


def main() -> None:
    configure_matplotlib()
    args = parse_args()

    repo_root = Path(args.repo_root).resolve()
    result_dir = (
        Path(args.result_dir).resolve()
        if args.result_dir
        else repo_root / "result" / "ch4" / "exp4_1_b"
    )
    out_dir = Path(args.out_dir).resolve() if args.out_dir else repo_root / "latex" / "pic"
    out_path = out_dir / args.out_name

    plot_delay_histogram(result_dir, out_path)


if __name__ == "__main__":
    main()
