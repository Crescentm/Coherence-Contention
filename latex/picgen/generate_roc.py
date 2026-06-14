#!/usr/bin/env python3
"""Generate the Chapter 4.2 ROC figure."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib import font_manager


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
        }
    )


def parse_stats(path: Path) -> dict[str, float]:
    values: dict[str, float] = {}
    for line in path.read_text().splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        try:
            values[key.strip()] = float(value.strip())
        except ValueError:
            continue
    return values


def parse_points(path: Path) -> tuple[list[float], list[float]]:
    pfa: list[float] = []
    pd: list[float] = []
    with path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            pfa.append(float(row["pfa"]))
            pd.append(float(row["pd"]))
    return pfa, pd


def parse_args() -> argparse.Namespace:
    repo_root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description="Generate ROC figure for Chapter 4.2.")
    parser.add_argument("--repo-root", default=str(repo_root))
    parser.add_argument("--out-dir", default="")
    return parser.parse_args()


def main() -> None:
    configure_matplotlib()
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()
    out_dir = Path(args.out_dir).resolve() if args.out_dir else repo_root / "latex" / "pic"
    out_dir.mkdir(parents=True, exist_ok=True)

    result_dir = repo_root / "result" / "ch4" / "exp4_2_d"
    stats = parse_stats(result_dir / "stats_42d.txt")
    pfa, pd = parse_points(result_dir / "roc_points_42d.csv")

    fig, ax = plt.subplots(figsize=(6.0, 5.2))
    ax.plot(pfa, pd, color="#E45756", linewidth=2.2, label=f"ROC (AUC={stats['auc']:.6f})")
    ax.plot([0.0, 1.0], [0.0, 1.0], linestyle="--", color="#666666", linewidth=1.0)
    ax.scatter(
        [stats["pfa_star"]],
        [stats["pd_star"]],
        color="#1F4E79",
        s=42,
        zorder=4,
        label=f"最优阈值 {stats['theta_star']:.0f} cycles",
    )

    ax.set_xlim(0.0, 1.0)
    ax.set_ylim(0.0, 1.02)
    ax.set_title("跨域一致性逐出信号的 ROC 曲线")
    ax.set_xlabel("误报率 $P_{FA}$")
    ax.set_ylabel("检测率 $P_D$")
    ax.grid(True, linestyle=":", alpha=0.45)
    ax.legend(loc="lower right")

    text = (
        f"AUC = {stats['auc']:.6f}\n"
        f"$\\theta^*$ = {stats['theta_star']:.0f} cycles\n"
        f"$P_D$ = {stats['pd_star'] * 100:.3f}%\n"
        f"$P_{{FA}}$ = {stats['pfa_star'] * 100:.4f}%"
    )
    ax.text(
        0.46,
        0.18,
        text,
        transform=ax.transAxes,
        bbox={"boxstyle": "round,pad=0.35", "facecolor": "white", "edgecolor": "#BBBBBB"},
    )

    fig.tight_layout()
    fig.savefig(out_dir / "roc_42d.png", bbox_inches="tight")
    plt.close(fig)


if __name__ == "__main__":
    main()
