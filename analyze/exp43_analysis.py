#!/usr/bin/env python3
"""
exp43_analysis.py — Chapter 4.3 analysis

Usage:
  python3 analyze/exp43_analysis.py --exp a --data-dir result/ch4/exp4_3_a
  python3 analyze/exp43_analysis.py --exp b --data-dir result/ch4/exp4_3_b
  python3 analyze/exp43_analysis.py --exp d --data-dir result/ch4/exp4_3_d
  python3 analyze/exp43_analysis.py --exp e --data-dir result/ch4/exp4_3_e
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

plt.rcParams["font.sans-serif"] = ["SimHei", "DejaVu Sans"]
plt.rcParams["axes.unicode_minus"] = False


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_A = REPO_ROOT / "result" / "ch4" / "exp4_3_a"
DEFAULT_B = REPO_ROOT / "result" / "ch4" / "exp4_3_b"
DEFAULT_D = REPO_ROOT / "result" / "ch4" / "exp4_3_d"
DEFAULT_E = REPO_ROOT / "result" / "ch4" / "exp4_3_e"


def load_cycles(path: Path, max_val: float = 5000.0) -> np.ndarray:
    vals: list[float] = []
    with path.open(newline="") as fp:
        reader = csv.reader(fp)
        for row in reader:
            if not row:
                continue
            try:
                v = float(row[0])
            except ValueError:
                continue
            if 0 <= v <= max_val:
                vals.append(v)
    return np.array(vals, dtype=float)


def roc_auc(h0: np.ndarray, h1: np.ndarray) -> tuple[np.ndarray, np.ndarray, float]:
    thresholds = np.unique(np.concatenate([h0, h1]))
    if thresholds.size == 0:
        return np.array([]), np.array([]), 0.0
    n0 = len(h0)
    n1 = len(h1)
    fa = np.array([np.sum(h0 > t) / n0 for t in thresholds], dtype=float)
    pd = np.array([np.sum(h1 > t) / n1 for t in thresholds], dtype=float)
    auc = float(np.trapz(pd[::-1], fa[::-1]))
    return fa, pd, auc


def snr(h0: np.ndarray, h1: np.ndarray) -> float:
    m0, m1 = float(np.mean(h0)), float(np.mean(h1))
    s0, s1 = float(np.std(h0)), float(np.std(h1))
    den = np.sqrt((s0 * s0 + s1 * s1) / 2.0)
    return float(abs(m1 - m0) / den) if den > 0 else 0.0


def outlier_ratio_3sigma(x: np.ndarray) -> float:
    if x.size == 0:
        return 0.0
    mu = float(np.mean(x))
    sigma = float(np.std(x))
    if sigma == 0:
        return 0.0
    return float(np.mean(np.abs(x - mu) > 3.0 * sigma))


def stats_row(name: str, h0: np.ndarray, h1: np.ndarray) -> dict[str, float | str]:
    _, _, auc = roc_auc(h0, h1)
    return {
        "condition": name,
        "n_h0": int(len(h0)),
        "n_h1": int(len(h1)),
        "mean_h0": float(np.mean(h0)),
        "std_h0": float(np.std(h0)),
        "mean_h1": float(np.mean(h1)),
        "std_h1": float(np.std(h1)),
        "snr": snr(h0, h1),
        "auc": auc,
        "outlier_ratio_h0_3sigma": outlier_ratio_3sigma(h0),
        "outlier_ratio_h1_3sigma": outlier_ratio_3sigma(h1),
    }


def write_summary(rows: list[dict], csv_path: Path, txt_path: Path):
    if not rows:
        raise SystemExit("[analysis] no rows to write")
    keys = list(rows[0].keys())
    with csv_path.open("w", newline="") as fp:
        wr = csv.DictWriter(fp, fieldnames=keys)
        wr.writeheader()
        for row in rows:
            wr.writerow(row)
    with txt_path.open("w") as fp:
        for row in rows:
            fp.write(f"[{row['condition']}]\n")
            for k in keys[1:]:
                fp.write(f"  {k}: {row[k]}\n")
            fp.write("\n")


def plot_overlay(ax: plt.Axes, h0: np.ndarray, h1: np.ndarray, title: str):
    xmin = min(float(np.min(h0)), float(np.min(h1)))
    xmax = max(float(np.max(h0)), float(np.max(h1)))
    if xmax <= xmin:
        xmax = xmin + 1.0
    bins = np.linspace(xmin, xmax, 80)
    ax.hist(h0, bins=bins, density=True, alpha=0.45, color="#1f77b4", label="H0")
    ax.hist(h1, bins=bins, density=True, alpha=0.45, color="#d62728", label="H1")
    ax.set_title(title)
    ax.set_xlabel("Latency (cycles)")
    ax.set_ylabel("Density")
    ax.grid(True, ls="--", alpha=0.3)
    ax.legend()


def require_pair(base: Path) -> tuple[np.ndarray, np.ndarray]:
    h0 = base / "raw_h0_cycles.csv"
    h1 = base / "raw_h1_cycles.csv"
    if not h0.exists() or not h1.exists():
        raise SystemExit(f"[missing] expected {h0} and {h1}")
    a0 = load_cycles(h0)
    a1 = load_cycles(h1)
    if len(a0) == 0 or len(a1) == 0:
        raise SystemExit(f"[empty] invalid data at {base}")
    return a0, a1


def analyze_a(data_dir: Path, out_dir: Path):
    conds = [
        ("idle", "空载"),
        ("cpu_full", "CPU 满载"),
        ("mem_bw", "内存带宽压力"),
        ("multi_vm", "多 VM 并发"),
    ]
    rows: list[dict] = []
    fig, axs = plt.subplots(2, 2, figsize=(12, 8))
    for i, (name, title) in enumerate(conds):
        h0, h1 = require_pair(data_dir / name)
        rows.append(stats_row(name, h0, h1))
        plot_overlay(axs[i // 2, i % 2], h0, h1, title)
    fig.tight_layout()
    fig.savefig(out_dir / "exp43a_2x2_distributions.png", dpi=300)
    plt.close(fig)

    write_summary(rows, out_dir / "summary_43a.csv", out_dir / "stats_43a.txt")


def analyze_b(data_dir: Path, out_dir: Path):
    conds = [("pinned_isolated", "绑核+隔离"), ("unpinned", "不绑核")]
    rows: list[dict] = []

    series = []
    labels = []
    for name, _title in conds:
        h0, h1 = require_pair(data_dir / name)
        rows.append(stats_row(name, h0, h1))
        series.extend([h0, h1])
        labels.extend([f"{name}\nH0", f"{name}\nH1"])

    fig, ax = plt.subplots(figsize=(9, 5))
    ax.boxplot(series, labels=labels, showfliers=False)
    ax.set_ylabel("Latency (cycles)")
    ax.set_title("4.3-B 调度与中断抖动影响（箱线图）")
    ax.grid(True, axis="y", ls="--", alpha=0.3)
    fig.tight_layout()
    fig.savefig(out_dir / "exp43b_boxplot.png", dpi=300)
    plt.close(fig)

    write_summary(rows, out_dir / "summary_43b.csv", out_dir / "stats_43b.txt")


def analyze_d(data_dir: Path, out_dir: Path):
    csv_path = data_dir / "granularity_degradation.csv"
    if not csv_path.exists():
        raise SystemExit(f"[missing] {csv_path}")

    rows: list[dict[str, str]] = []
    with csv_path.open(newline="") as fp:
        reader = csv.DictReader(fp)
        rows = list(reader)
    if not rows:
        raise SystemExit(f"[empty] {csv_path}")

    labels = [r["granularity"] for r in rows]
    accs = [float(r["best_accuracy"]) for r in rows]
    aucs = [float(r["auc"]) for r in rows]
    deltas = [float(r["delta"]) for r in rows]

    fig, ax1 = plt.subplots(figsize=(8, 4.6))
    x = np.arange(len(labels))
    ax1.plot(x, accs, marker="o", linewidth=2, label="Best Accuracy")
    ax1.plot(x, aucs, marker="s", linewidth=2, label="AUC")
    ax1.set_xticks(x)
    ax1.set_xticklabels(labels)
    ax1.set_ylim(0.0, 1.05)
    ax1.set_ylabel("Score")
    ax1.grid(True, linestyle=":", alpha=0.5)

    ax2 = ax1.twinx()
    ax2.plot(x, deltas, marker="^", linewidth=1.8, color="#2ca02c", label="Delta (cycles)")
    ax2.set_ylabel("Delta Cycles")
    ax2.grid(False)

    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc="best")
    ax1.set_title("4.3-D Signal Degradation vs Granularity")
    fig.tight_layout()
    fig.savefig(out_dir / "exp43d_degradation.png", dpi=300)
    plt.close(fig)

    out_txt = out_dir / "stats_43d_analysis.txt"
    with out_txt.open("w") as fp:
        for r in rows:
            fp.write(
                f"[{r['granularity']}] best_accuracy={r['best_accuracy']} auc={r['auc']} "
                f"delta={r['delta']} threshold={r['best_threshold']}\n"
            )


def load_pattern_csv(path: Path) -> np.ndarray:
    arr: list[list[int]] = []
    with path.open(newline="") as fp:
        reader = csv.reader(fp)
        next(reader, None)
        for row in reader:
            if not row:
                continue
            arr.append([int(x) for x in row[1:]])
    mat = np.array(arr, dtype=int)
    if mat.ndim != 2 or mat.shape[0] == 0 or mat.shape[0] != mat.shape[1]:
        raise SystemExit(f"[pattern] expected non-empty square matrix, got {mat.shape} in {path}")
    return mat


def analyze_e(data_dir: Path, out_dir: Path, labels: list[str]):
    coh_rows: list[dict] = []
    ctn_rows: list[dict] = []

    available_patterns: list[tuple[str, np.ndarray]] = []
    for lb in labels:
        lb_dir = data_dir / lb
        if not lb_dir.exists():
            continue

        pat_path = lb_dir / "eviction_pattern_binary.csv"
        coh_dir = lb_dir / "coherence"
        ctn_dir = lb_dir / "contention"
        if pat_path.exists():
            available_patterns.append((lb, load_pattern_csv(pat_path)))
        if (coh_dir / "raw_h0_cycles.csv").exists() and (coh_dir / "raw_h1_cycles.csv").exists():
            h0, h1 = require_pair(coh_dir)
            coh_rows.append(stats_row(lb, h0, h1))
        if (ctn_dir / "raw_h0_cycles.csv").exists() and (ctn_dir / "raw_h1_cycles.csv").exists():
            h0, h1 = require_pair(ctn_dir)
            ctn_rows.append(stats_row(lb, h0, h1))

    if available_patterns:
        n = min(4, len(available_patterns))
        fig, axs = plt.subplots(2, 2, figsize=(10, 10))
        cmap = matplotlib.colors.ListedColormap(["white", "black"])
        for i in range(4):
            ax = axs[i // 2, i % 2]
            if i < n:
                lb, mat = available_patterns[i]
                ax.imshow(mat, cmap=cmap, origin="lower", interpolation="nearest", aspect="equal", vmin=0, vmax=1)
                ax.set_title(lb)
                ax.set_xlabel("Ciphertext Line")
                ax.set_ylabel("Plaintext Line")
            else:
                ax.axis("off")
        fig.suptitle("4.3-E Eviction Pattern (black=eviction, white=no eviction)")
        fig.tight_layout()
        fig.savefig(out_dir / "exp43e_eviction_pattern_2x2.png", dpi=300)
        plt.close(fig)

    if coh_rows:
        write_summary(coh_rows, out_dir / "summary_43e_coherence.csv", out_dir / "stats_43e_coherence.txt")
    if ctn_rows:
        write_summary(ctn_rows, out_dir / "summary_43e_contention.csv", out_dir / "stats_43e_contention.txt")

    if coh_rows and ctn_rows:
        c_by = {str(r["condition"]): r for r in coh_rows}
        t_by = {str(r["condition"]): r for r in ctn_rows}
        common = [lb for lb in labels if lb in c_by and lb in t_by]
        out_rows = []
        for lb in common:
            out_rows.append(
                {
                    "interleave": lb,
                    "snr_coherence": c_by[lb]["snr"],
                    "auc_coherence": c_by[lb]["auc"],
                    "snr_contention": t_by[lb]["snr"],
                    "auc_contention": t_by[lb]["auc"],
                    "snr_delta_coh_minus_ctn": float(c_by[lb]["snr"]) - float(t_by[lb]["snr"]),
                    "auc_delta_coh_minus_ctn": float(c_by[lb]["auc"]) - float(t_by[lb]["auc"]),
                }
            )
        with (out_dir / "summary_43e_compare.csv").open("w", newline="") as fp:
            wr = csv.DictWriter(fp, fieldnames=list(out_rows[0].keys()) if out_rows else [])
            if out_rows:
                wr.writeheader()
                wr.writerows(out_rows)


def main():
    ap = argparse.ArgumentParser(description="Analyze Chapter 4.3 results")
    ap.add_argument("--exp", choices=["a", "b", "d", "e"], required=True)
    ap.add_argument("--data-dir", default="")
    ap.add_argument("--out-dir", default="")
    ap.add_argument("--labels", default="256B,512B,1024B,2048B")
    args = ap.parse_args()

    if args.exp == "a":
        data_dir = Path(args.data_dir) if args.data_dir else DEFAULT_A
    elif args.exp == "b":
        data_dir = Path(args.data_dir) if args.data_dir else DEFAULT_B
    elif args.exp == "d":
        data_dir = Path(args.data_dir) if args.data_dir else DEFAULT_D
    else:
        data_dir = Path(args.data_dir) if args.data_dir else DEFAULT_E

    out_dir = Path(args.out_dir) if args.out_dir else data_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"[analysis] exp={args.exp} data_dir={data_dir} out_dir={out_dir}")
    if args.exp == "a":
        analyze_a(data_dir, out_dir)
    elif args.exp == "b":
        analyze_b(data_dir, out_dir)
    elif args.exp == "d":
        analyze_d(data_dir, out_dir)
    else:
        labels = [x.strip() for x in args.labels.split(",") if x.strip()]
        analyze_e(data_dir, out_dir, labels)
    print("[analysis] done")


if __name__ == "__main__":
    main()
