"""
exp42aplus_analysis.py — 实验 4.2-A+：64条缓存行信号强度热力图

复用现有 64×64 矩阵数据（默认 amd_ciphertext_20260324_181542）。

指标计算策略:
  - H1 信号  = same_page_matrix 对角线 mean (victim_line i, probe_line i)
  - H0 基线  = other_page_matrix 对角线 mean (victim_line i, probe_line i)
  - p_gt_t   = same_page victim_line_XX/same_page/line_matrix_row.csv 的
               对角线 p_gt_t (fraction of reps > threshold)
  - SNR      = |H1_mean - H0_mean| / sqrt((std_H1^2 + std_H0^2)/2)
               用 mean ± std 近似：std ≈ (max-min)/4 （粗估）
               或直接用 (H1_mean - H0_mean) / H0_mean 相对增量

产出:
  - exp42aplus_heatmap.png     — 8×8 热力图（缓存行编号 vs 信号强度）
  - exp42aplus_snr_bar.png     — 每条缓存行 SNR 柱状图
  - exp42aplus_pgtt_bar.png    — 每条缓存行 p_gt_t 柱状图
  - exp42aplus_stats.csv       — 各缓存行统计表
"""

import csv
import os
import sys
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib import font_manager


def configure_plot_style() -> str:
    """配置统一绘图风格，并尽可能选择可用中文字体。"""
    preferred_cjk_fonts = [
        "Noto Sans CJK SC",
        "Noto Sans CJK TC",
        "Noto Sans CJK JP",
        "Microsoft YaHei",
        "WenQuanYi Zen Hei",
        "PingFang SC",
        "SimHei",
        "AR PL UMing CN",
        "Droid Sans Fallback",
    ]
    available = {f.name for f in font_manager.fontManager.ttflist}
    cjk_font = next((name for name in preferred_cjk_fonts if name in available), "DejaVu Sans")

    plt.rcParams.update({
        "font.family": "sans-serif",
        "font.sans-serif": [cjk_font, "DejaVu Sans"],
        "axes.unicode_minus": False,
        "figure.dpi": 130,
        "savefig.dpi": 300,
        "savefig.facecolor": "white",
        "figure.facecolor": "white",
        "axes.facecolor": "white",
        "axes.edgecolor": "#D0D7DE",
        "axes.linewidth": 0.8,
        "grid.color": "#E5E7EB",
        "grid.linestyle": "--",
        "grid.linewidth": 0.8,
        "axes.titlesize": 13,
        "axes.labelsize": 11,
        "xtick.labelsize": 9,
        "ytick.labelsize": 9,
    })
    return cjk_font


ACTIVE_FONT = configure_plot_style()


# ─── 路径配置 ─────────────────────────────────────────────────────────────────
REPO_ROOT   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULT_ROOT = os.path.join(REPO_ROOT, "..", "result")

# 默认数据源与输出目录
DEFAULT_DATA_DIR = os.path.join(RESULT_ROOT, "amd_ciphertext_20260324_181542")
DEFAULT_OUT_DIR  = os.path.join(RESULT_ROOT, "ch4", "exp4_2_aplus")

# 自动搜索顺序（当默认数据不存在时）
CANDIDATE_DIRS = [
    DEFAULT_DATA_DIR,
    os.path.join(RESULT_ROOT, "amd_ciphertext_20260324_175523"),
    os.path.join(RESULT_ROOT, "ch4", "exp4_2_a"),
    os.path.join(RESULT_ROOT, "ch4", "exp4_1_b"),
]

N_LINES = 64  # 缓存行数


# ─── 数据加载 ─────────────────────────────────────────────────────────────────
def load_matrix_csv(path: str) -> dict:
    """
    读取 same_page_matrix.csv / other_page_matrix.csv。
    返回 dict: victim_line (int) -> list[float] (64 列 mean_cycles)
    """
    result = {}
    with open(path, newline="") as f:
        reader = csv.reader(f)
        header = next(reader)
        for row in reader:
            if not row:
                continue
            try:
                vl = int(row[0])
                vals = [float(x) for x in row[1:]]
                result[vl] = vals
            except (ValueError, IndexError):
                pass
    return result


def load_per_line_stats(data_dir: str) -> dict:
    """
    从 victim_line_XX/same_page/line_matrix_row.csv 读取 per-(victim,probe) 统计。
    返回 dict: victim_line -> dict: probe_line -> {mean, min, max, p_gt_t, reps}
    """
    result = {}
    for vl in range(N_LINES):
        row_path = os.path.join(data_dir,
                                f"victim_line_{vl:02d}",
                                "same_page",
                                "line_matrix_row.csv")
        if not os.path.exists(row_path):
            continue
        result[vl] = {}
        with open(row_path, newline="") as f:
            reader = csv.DictReader(f)
            for rec in reader:
                try:
                    hl = int(rec["host_line"])
                    result[vl][hl] = {
                        "mean":  float(rec["mean_cycles"]),
                        "min":   float(rec["min_cycles"]),
                        "max":   float(rec["max_cycles"]),
                        "p_gt_t": float(rec["p_gt_t"]),
                        "reps":  int(rec["reps"]),
                    }
                except (KeyError, ValueError):
                    pass
    return result


def load_other_page_matrix(data_dir: str) -> dict:
    """读取 other_page_matrix.csv（跨页基线）。"""
    path = os.path.join(data_dir, "other_page_matrix.csv")
    if not os.path.exists(path):
        return {}
    return load_matrix_csv(path)


def load_same_page_matrix(data_dir: str) -> dict:
    """读取 same_page_matrix.csv。"""
    path = os.path.join(data_dir, "same_page_matrix.csv")
    if not os.path.exists(path):
        return {}
    return load_matrix_csv(path)


# ─── 衍生指标 ─────────────────────────────────────────────────────────────────
def derive_per_line_metrics(same_mat: dict, other_mat: dict,
                            per_line_stats: dict) -> list:
    """
    对每条缓存行 i 计算:
      h1_mean  = same_mat[i][i]   (victim=i probe=i → eviction signal)
      h0_mean  = other_mat[i][i]  (victim=i probe=i 的跨页基线)
      p_gt_t   = per_line_stats[i][i].p_gt_t
      snr_db   = 20*log10(h1_mean / h0_mean)
      delta    = h1_mean - h0_mean
    """
    rows = []
    for i in range(N_LINES):
        h1 = same_mat.get(i, [None] * N_LINES)
        h0 = other_mat.get(i, [None] * N_LINES)

        # 从矩阵读对角值
        h1_diag = h1[i] if h1 and i < len(h1) else None
        h0_diag = h0[i] if h0 and i < len(h0) else None

        # p_gt_t from per-line stats
        pgtt = None
        if i in per_line_stats and i in per_line_stats[i]:
            pgtt = per_line_stats[i][i]["p_gt_t"]
        elif h1_diag is not None:
            # 粗估：若 mean > 400 → 大概率为 H1 大部分高于阈值
            pgtt = 1.0 if h1_diag > 400 else 0.0

        # SNR = delta / h0_mean
        if h1_diag is not None and h0_diag is not None and h0_diag > 0:
            delta = h1_diag - h0_diag
            snr   = delta / h0_diag  # 相对增量 (0~...)
        else:
            delta = None
            snr   = None

        rows.append({
            "line":    i,
            "h1_mean": h1_diag,
            "h0_mean": h0_diag,
            "delta":   delta,
            "snr":     snr,
            "p_gt_t":  pgtt,
        })
    return rows


def dict_to_matrix64(data_dict: dict, *, stats_mode: bool = False,
                     stats_key: str = "p_gt_t") -> np.ndarray:
    """将 dict 结构统一转为 64x64 矩阵。缺失值填 NaN。"""
    mat = np.full((N_LINES, N_LINES), np.nan, dtype=float)
    if stats_mode:
        for vl, row_map in data_dict.items():
            if not (0 <= vl < N_LINES):
                continue
            for hl, rec in row_map.items():
                if not (0 <= hl < N_LINES):
                    continue
                try:
                    mat[vl, hl] = float(rec[stats_key])
                except (KeyError, TypeError, ValueError):
                    continue
        return mat

    for vl, row in data_dict.items():
        if not (0 <= vl < N_LINES):
            continue
        for hl, v in enumerate(row[:N_LINES]):
            try:
                mat[vl, hl] = float(v)
            except (TypeError, ValueError):
                continue
    return mat


# ─── 绘图 ────────────────────────────────────────────────────────────────────
def plot_heatmap_64x64(matrix: np.ndarray, out_path: str, *,
                       title: str, cmap: str, colorbar_label: str):
    """绘制完整 64x64 热力图（victim_line × host_line）。"""
    data = np.array(matrix, dtype=float)
    valid = data[np.isfinite(data)]
    if valid.size == 0:
        print(f"  [跳过] {out_path}（无有效数据）")
        return

    vmin = float(np.percentile(valid, 1))
    vmax = float(np.percentile(valid, 99))
    if vmax <= vmin:
        vmax = vmin + 1.0

    fig, ax = plt.subplots(figsize=(9.2, 8.4))
    masked = np.ma.masked_invalid(data)
    cm = plt.get_cmap(cmap).copy()
    cm.set_bad("#F5F7FA")

    im = ax.imshow(
        masked,
        cmap=cm,
        aspect="equal",
        interpolation="nearest",
        origin="lower",
        vmin=vmin,
        vmax=vmax,
    )
    cbar = plt.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    cbar.set_label(colorbar_label, fontsize=10)
    cbar.ax.tick_params(labelsize=8)
    cbar.outline.set_linewidth(0.6)
    cbar.outline.set_edgecolor("#D0D7DE")

    # 每8条线一个主刻度，视觉更接近 same_page_heatmap_tsc.svg 的块状结构
    major_ticks = list(range(0, N_LINES, 8))
    ax.set_xticks(major_ticks)
    ax.set_yticks(major_ticks)
    ax.set_xlabel("Host Line (Accessed)", fontsize=10)
    ax.set_ylabel("Victim Line (Measured)", fontsize=10)
    ax.set_title(
        f"{title}\nmin={np.nanmin(data):.1f} max={np.nanmax(data):.1f}",
        fontsize=12,
    )

    # 单格细网格 + 8x8 粗分块网格，突出棋盘块纹理
    ax.set_xticks(np.arange(-0.5, N_LINES, 1), minor=True)
    ax.set_yticks(np.arange(-0.5, N_LINES, 1), minor=True)
    ax.grid(which="minor", color="white", linestyle="-", linewidth=0.15, alpha=0.55)
    for t in np.arange(-0.5, N_LINES, 8):
        ax.axhline(t, color="white", linewidth=0.9, alpha=0.9)
        ax.axvline(t, color="white", linewidth=0.9, alpha=0.9)
    ax.tick_params(which="minor", bottom=False, left=False)

    fig.tight_layout()
    fig.savefig(out_path, dpi=300, bbox_inches="tight")
    svg_out = os.path.splitext(out_path)[0] + ".svg"
    fig.savefig(svg_out, bbox_inches="tight")
    plt.close(fig)
    print(f"  [图] {out_path}")
    print(f"  [图] {svg_out}")


def plot_bar(metrics: list, key: str, ylabel: str, title: str, out_path: str,
             top_n: int = 5):
    vals = [m[key] if m[key] is not None else 0.0 for m in metrics]
    xs   = list(range(N_LINES))

    # 找 Top-N
    top_idx = sorted(range(N_LINES), key=lambda i: vals[i] if vals[i] else -1,
                     reverse=True)[:top_n]

    colors = ["#d62728" if i in top_idx else "#1f77b4" for i in xs]

    fig, ax = plt.subplots(figsize=(13.5, 4.6))
    ax.bar(xs, vals, color=colors, width=0.8)
    ax.set_xlabel("缓存行编号", fontsize=11)
    ax.set_ylabel(ylabel, fontsize=11)
    ax.set_title(title, fontsize=12)
    ax.set_xticks(range(0, N_LINES, 4))
    ax.grid(True, axis="y", ls="--", alpha=0.6)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    # 标注 Top-N
    vmax = max(vals) if vals else 1.0
    for i in top_idx:
        ax.text(i, vals[i] + vmax * 0.01,
                f"L{i}", ha="center", va="bottom", fontsize=7, color="darkred")

    fig.tight_layout()
    fig.savefig(out_path, dpi=300, bbox_inches="tight")
    svg_out = os.path.splitext(out_path)[0] + ".svg"
    fig.savefig(svg_out, bbox_inches="tight")
    plt.close(fig)
    print(f"  [图] {out_path}")
    print(f"  [图] {svg_out}")


# ─── 主程序 ──────────────────────────────────────────────────────────────────
def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", default="",
                    help=f"包含 same_page_matrix.csv 的目录（默认: {DEFAULT_DATA_DIR}）")
    ap.add_argument("--out-dir",  default="",
                    help=f"图片输出目录（默认: {DEFAULT_OUT_DIR}）")
    args = ap.parse_args()

    # 确定数据目录
    if args.data_dir:
        data_dir = os.path.abspath(args.data_dir)
    else:
        data_dir = None
        for d in CANDIDATE_DIRS:
            if os.path.exists(os.path.join(d, "same_page_matrix.csv")):
                data_dir = d
                break
        if data_dir is None:
            sys.exit("错误：找不到 same_page_matrix.csv，请先运行 run_42aplus.sh 或确认路径。")

    print(f"[数据目录] {data_dir}")
    out_dir = os.path.abspath(args.out_dir) if args.out_dir else os.path.abspath(DEFAULT_OUT_DIR)
    print(f"[输出目录] {out_dir}")
    print(f"[字体] {ACTIVE_FONT}")
    os.makedirs(out_dir, exist_ok=True)

    # 加载矩阵
    same_mat   = load_same_page_matrix(data_dir)
    other_mat  = load_other_page_matrix(data_dir)
    per_stats  = load_per_line_stats(data_dir)

    if not same_mat:
        sys.exit("错误：same_page_matrix.csv 为空或解析失败。")

    # 计算指标
    metrics = derive_per_line_metrics(same_mat, other_mat, per_stats)

    # 打印统计
    print(f"\n=== 实验 4.2-A+：各缓存行信号指标 ===========================")
    print(f"{'Line':>5} {'H1_mean':>9} {'H0_mean':>9} {'Delta':>8} {'SNR(rel)':>10} {'p_gt_t':>8}")
    for m in metrics:
        line = m["line"]
        h1   = f"{m['h1_mean']:.1f}" if m["h1_mean"] is not None else "N/A"
        h0   = f"{m['h0_mean']:.1f}" if m["h0_mean"] is not None else "N/A"
        d    = f"{m['delta']:.1f}"   if m["delta"]   is not None else "N/A"
        snr  = f"{m['snr']:.3f}"     if m["snr"]     is not None else "N/A"
        pg   = f"{m['p_gt_t']:.3f}"  if m["p_gt_t"]  is not None else "N/A"
        print(f"  {line:3d}   {h1:>9} {h0:>9} {d:>8} {snr:>10} {pg:>8}")

    # Top-5 信号最强缓存行
    valid = [m for m in metrics if m["delta"] is not None]
    top5  = sorted(valid, key=lambda m: m["delta"], reverse=True)[:5]
    print(f"\nTop-5 信号最强缓存行 (按 delta):")
    for rank, m in enumerate(top5, 1):
        print(f"  #{rank}: 缓存行 {m['line']:2d}  delta={m['delta']:.1f} cycles  "
              f"p_gt_t={m['p_gt_t']:.3f}")

    # 生成 64×64 热力图（与 same_page_heatmap_tsc.svg 同级别表达）
    same_full = dict_to_matrix64(same_mat)
    other_full = dict_to_matrix64(other_mat) if other_mat else np.full((N_LINES, N_LINES), np.nan)
    pgtt_full = dict_to_matrix64(per_stats, stats_mode=True, stats_key="p_gt_t")
    if np.isfinite(other_full).any():
        delta_full = same_full - other_full
    else:
        print("  [提示] other_page_matrix.csv 缺失，delta 热力图改为 same_page 原值。")
        delta_full = same_full

    plot_heatmap_64x64(
        same_full,
        os.path.join(out_dir, "exp42aplus_same_heatmap_64x64.png"),
        title="实验 4.2-A+：Same-Page 64×64 热力图",
        cmap="viridis",
        colorbar_label="Mean cycles",
    )
    plot_heatmap_64x64(
        delta_full,
        os.path.join(out_dir, "exp42aplus_delta_heatmap.png"),
        title="实验 4.2-A+：Delta(H1-H0) 64×64 热力图",
        cmap="coolwarm",
        colorbar_label="Delta cycles",
    )
    plot_heatmap_64x64(
        pgtt_full,
        os.path.join(out_dir, "exp42aplus_pgtt_heatmap.png"),
        title="实验 4.2-A+：p_gt_t 64×64 热力图",
        cmap="YlGnBu",
        colorbar_label="p_gt_t",
    )
    plot_bar(metrics, key="delta",  ylabel="逐出延迟差 (cycles)",
             title="实验 4.2-A+：各缓存行信号强度 (H1-H0)",
             out_path=os.path.join(out_dir, "exp42aplus_delta_bar.png"))
    plot_bar(metrics, key="p_gt_t", ylabel="检测率 p_gt_t",
             title="实验 4.2-A+：各缓存行检测率 p_gt_t",
             out_path=os.path.join(out_dir, "exp42aplus_pgtt_bar.png"))

    # 输出统计 CSV
    stats_csv_path = os.path.join(out_dir, "exp42aplus_stats.csv")
    with open(stats_csv_path, "w", newline="") as f:
        wr = csv.writer(f)
        wr.writerow(["line", "h1_mean", "h0_mean", "delta", "snr_rel", "p_gt_t"])
        for m in metrics:
            wr.writerow([m["line"],
                         f"{m['h1_mean']:.3f}" if m["h1_mean"] is not None else "",
                         f"{m['h0_mean']:.3f}" if m["h0_mean"] is not None else "",
                         f"{m['delta']:.3f}"   if m["delta"]   is not None else "",
                         f"{m['snr']:.4f}"     if m["snr"]     is not None else "",
                         f"{m['p_gt_t']:.4f}"  if m["p_gt_t"]  is not None else ""])
    print(f"\n  [统计] {stats_csv_path}")


if __name__ == "__main__":
    main()
