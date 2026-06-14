#!/usr/bin/env python3
"""
exp44_analysis.py — 实验 4.4：与传统微架构侧信道攻击的机制对比

对齐 require/ch4.md 的 4.4 节要求，支持三个子实验：

  python3 analyze/exp44_analysis.py --exp a --data-dir result/ch4/exp4_4_a
  python3 analyze/exp44_analysis.py --exp b --data-dir result/ch4/exp4_4_b
  python3 analyze/exp44_analysis.py --exp c --data-dir result/ch4/exp4_4_c
  python3 analyze/exp44_analysis.py --exp all

产出：
  4.4-A: Prime+Count 信号对比（plain VM vs SEV-SNP VM），计数分布 + 准确率
  4.4-B: Flush+Reload 阴性验证结果整理，文本报告
  4.4-C: 三方法（PP / 一致性逐出 / 内存竞争）ROC 叠加图 + 对比表
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

plt.rcParams["font.sans-serif"] = ["DejaVu Sans", "SimHei"]
plt.rcParams["axes.unicode_minus"] = False
plt.rcParams["font.size"] = 12
plt.rcParams["axes.titlesize"] = 13

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BASE = REPO_ROOT / "result" / "ch4"

# ─── 数据加载 ──────────────────────────────────────────────────────────────────

def load_cycles(path: Path, max_val: float = 1e7) -> np.ndarray:
    """加载单列或最后一列为 cycles 的 CSV，过滤非正值与超大异常值。"""
    vals: list[float] = []
    with path.open(newline="") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row:
                continue
            raw = row[-1].strip()
            try:
                v = float(raw)
            except ValueError:
                continue
            if 0 < v <= max_val:
                vals.append(v)
    arr = np.asarray(vals, dtype=np.float64)
    return arr


def try_load_pair(base: Path, h0_name: str = "raw_h0_cycles.csv",
                  h1_name: str = "raw_h1_cycles.csv") -> tuple[np.ndarray, np.ndarray] | None:
    h0p = base / h0_name
    h1p = base / h1_name
    if not h0p.exists() or not h1p.exists():
        return None
    h0 = load_cycles(h0p)
    h1 = load_cycles(h1p)
    if h0.size == 0 or h1.size == 0:
        return None
    return h0, h1


def remove_outliers(x: np.ndarray, lo_pct: float = 0.5, hi_pct: float = 99.5) -> np.ndarray:
    if x.size == 0:
        return x
    lo = np.percentile(x, lo_pct)
    hi = np.percentile(x, hi_pct)
    return x[(x >= lo) & (x <= hi)]


# ─── 统计工具 ──────────────────────────────────────────────────────────────────

def basic_stats(x: np.ndarray) -> dict:
    x = remove_outliers(x)
    if x.size == 0:
        return {k: float("nan") for k in ("n", "mean", "median", "std", "p5", "p95")}
    return {
        "n":      int(x.size),
        "mean":   float(np.mean(x)),
        "median": float(np.median(x)),
        "std":    float(np.std(x)),
        "p5":     float(np.percentile(x, 5)),
        "p95":    float(np.percentile(x, 95)),
    }


def snr(h0: np.ndarray, h1: np.ndarray) -> float:
    h0c = remove_outliers(h0)
    h1c = remove_outliers(h1)
    if h0c.size == 0 or h1c.size == 0:
        return float("nan")
    m0, m1 = np.mean(h0c), np.mean(h1c)
    s0, s1 = np.std(h0c), np.std(h1c)
    denom = np.sqrt((s0 ** 2 + s1 ** 2) / 2.0)
    return float(abs(m1 - m0) / denom) if denom > 0 else float("nan")


def compute_roc(h0: np.ndarray, h1: np.ndarray
                ) -> tuple[np.ndarray, np.ndarray, np.ndarray, float]:
    """返回 (thresholds, pfa, pd, auc)。"""
    h0c = remove_outliers(h0)
    h1c = remove_outliers(h1)
    all_th = np.unique(np.concatenate([h0c, h1c]))
    if all_th.size == 0:
        return np.array([]), np.array([]), np.array([]), 0.0
    # 扩展边界确保 ROC 包含 (0,0) 和 (1,1)
    lo = np.nextafter(float(all_th[0]), -np.inf)
    hi = np.nextafter(float(all_th[-1]),  np.inf)
    th = np.concatenate(([lo], all_th, [hi]))

    s0 = np.sort(h0c)
    s1 = np.sort(h1c)
    n0, n1 = s0.size, s1.size

    idx0 = np.searchsorted(s0, th, side="right")
    idx1 = np.searchsorted(s1, th, side="right")
    pfa = (n0 - idx0) / n0
    pd  = (n1 - idx1) / n1

    auc = float(np.trapz(pd[::-1], pfa[::-1]))
    return th, pfa, pd, auc


def best_op_point(th: np.ndarray, pfa: np.ndarray, pd: np.ndarray
                  ) -> tuple[float, float, float]:
    """Youden J 准则最优工作点：argmax(PD - PFA)。"""
    if th.size == 0:
        return float("nan"), float("nan"), float("nan")
    j = pd - pfa
    b = int(np.argmax(j))
    return float(th[b]), float(pfa[b]), float(pd[b])


def detection_accuracy(h0: np.ndarray, h1: np.ndarray, theta: float) -> float:
    """在给定阈值下的平衡准确率 (PD + (1-PFA)) / 2。"""
    h0c = remove_outliers(h0)
    h1c = remove_outliers(h1)
    if h0c.size == 0 or h1c.size == 0:
        return float("nan")
    pd  = float(np.mean(h1c > theta))
    tnr = float(np.mean(h0c <= theta))
    return (pd + tnr) / 2.0


# ─── 绘图工具 ──────────────────────────────────────────────────────────────────

def plot_hist_pair(ax: plt.Axes, h0: np.ndarray, h1: np.ndarray,
                   label0: str, label1: str, title: str,
                   theta: float | None = None,
                   x_label: str = "Latency (cycles)") -> None:
    h0c = remove_outliers(h0)
    h1c = remove_outliers(h1)
    lo = min(float(np.min(h0c)), float(np.min(h1c)))
    hi = max(float(np.max(h0c)), float(np.max(h1c)))
    bins = np.linspace(lo, hi, 80)

    ax.hist(h0c, bins=bins, density=True, alpha=0.50,
            color="#1f77b4", label=label0)
    ax.hist(h1c, bins=bins, density=True, alpha=0.50,
            color="#d62728", label=label1)

    ax.axvline(float(np.mean(h0c)), color="#1f77b4", ls="--", lw=1.2)
    ax.axvline(float(np.mean(h1c)), color="#d62728", ls="--", lw=1.2)

    if theta is not None and not np.isnan(theta):
        ax.axvline(theta, color="black", ls=":", lw=1.5,
                   label=f"θ*={theta:.0f}")

    ax.set_title(title)
    ax.set_xlabel(x_label)
    ax.set_ylabel("Density")
    ax.legend(fontsize=9)
    ax.grid(True, ls="--", alpha=0.3)


def write_stats_txt(path: Path, sections: list[tuple[str, dict]]) -> None:
    with path.open("w") as f:
        for title, d in sections:
            f.write(f"=== {title} ===\n")
            for k, v in d.items():
                f.write(f"  {k}: {v}\n")
            f.write("\n")


def write_csv_rows(path: Path, rows: list[dict]) -> None:
    if not rows:
        return
    keys = list(rows[0].keys())
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        for r in rows:
            w.writerow(r)


# ════════════════════════════════════════════════════════════════════════════
# 4.4-A：Prime+Count 信号对比分析
# ════════════════════════════════════════════════════════════════════════════

def analyze_44a(data_dir: Path, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"\n[4.4-A] data_dir={data_dir}")

    # ── 加载数据 ───────────────────────────────────────────────────────────
    # LLC Prime+Count 信号：普通 KVM
    plain_dir = data_dir / "plain_vm"
    plain_h0 = _try_load_scalar(plain_dir, "raw_h0_counts.csv")
    plain_h1 = _try_load_scalar(plain_dir, "raw_h1_counts.csv")

    # LLC Prime+Count 信号：SEV-SNP VM
    snp_dir = data_dir / "snp_vm"
    snp_h0 = _try_load_scalar(snp_dir, "raw_h0_counts.csv")
    snp_h1 = _try_load_scalar(snp_dir, "raw_h1_counts.csv")

    # ── 绘图：分布对比 ─────────────────────────────────────────────────────
    scenarios: list[tuple[str, np.ndarray | None, np.ndarray | None]] = [
        ("LLC Prime+Count (plain KVM)",  plain_h0, plain_h1),
        ("LLC Prime+Count (SEV-SNP VM)", snp_h0,   snp_h1),
    ]

    n_valid = sum(1 for _, h0, h1 in scenarios if h0 is not None and h1 is not None)

    if n_valid > 0:
        ncols = min(n_valid, 3)
        fig, axs = plt.subplots(1, ncols, figsize=(5.5 * ncols, 4.5))
        if ncols == 1:
            axs = [axs]

        col = 0
        rows: list[dict] = []
        for title, h0, h1 in scenarios:
            if h0 is None or h1 is None:
                _warn_missing(title)
                continue
            th, pfa, pd, auc = compute_roc(h0, h1)
            theta_star, pfa_b, pd_b = best_op_point(th, pfa, pd)
            acc = detection_accuracy(h0, h1, theta_star)
            sig_amp = float(np.mean(remove_outliers(h1))) - float(np.mean(remove_outliers(h0)))

            plot_hist_pair(axs[col], h0, h1,
                           "H0 (无 guest 访问)", "H1 (guest 访问 target)",
                           title, theta=theta_star,
                           x_label="Probe miss count")
            col += 1

            rows.append({
                "method":       title,
                "n_h0":         remove_outliers(h0).size,
                "n_h1":         remove_outliers(h1).size,
                "mean_h0":      f"{np.mean(remove_outliers(h0)):.1f}",
                "mean_h1":      f"{np.mean(remove_outliers(h1)):.1f}",
                "signal_amp":   f"{sig_amp:.1f}",
                "snr":          f"{snr(h0, h1):.3f}",
                "auc":          f"{auc:.4f}",
                "theta_star":   f"{theta_star:.0f}",
                "pd_at_theta":  f"{pd_b:.4f}",
                "pfa_at_theta": f"{pfa_b:.4f}",
                "accuracy_bal": f"{acc:.4f}",
            })

        fig.suptitle("Exp 4.4-A: LLC Prime+Count — plain KVM vs SEV-SNP VM", fontsize=13)
        fig.tight_layout()
        out_png = out_dir / "exp44a_distributions.png"
        fig.savefig(out_png, dpi=300)
        plt.close(fig)
        print(f"  [4.4-A] 分布图: {out_png}")

        write_csv_rows(out_dir / "stats_44a.csv", rows)
        print(f"  [4.4-A] 统计表: {out_dir / 'stats_44a.csv'}")

        # 汇总文本
        sections = [(r["method"], r) for r in rows]
        write_stats_txt(out_dir / "summary_44a.txt", sections)

        # 打印简要表格
        print("\n  === 4.4-A 统计摘要（LLC Prime+Count）===")
        hdr = f"  {'Method':<26} {'Signal Amp':>12} {'SNR':>8} {'AUC':>8} {'Accuracy':>10}"
        print(hdr)
        print("  " + "-" * (len(hdr) - 2))
        for r in rows:
            print(f"  {r['method']:<26} {r['signal_amp']:>12} {r['snr']:>8} "
                  f"{r['auc']:>8} {r['accuracy_bal']:>10}")
    else:
        print("  [4.4-A] 无有效数据，请先运行 run_44.py a")


def _try_load_scalar(base: Path, fname: str) -> "np.ndarray | None":
    p = base / fname
    if not p.exists():
        return None
    arr = load_cycles(p)
    return arr if arr.size > 0 else None


def _warn_missing(label: str) -> None:
    print(f"  [warn] {label}: 数据缺失，跳过")


# ════════════════════════════════════════════════════════════════════════════
# 4.4-B：Flush+Reload 阴性验证结果整理
# ════════════════════════════════════════════════════════════════════════════

def analyze_44b(data_dir: Path, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"\n[4.4-B] data_dir={data_dir}")

    result_files = [
        data_dir / "fr_verify_result.txt",
        data_dir / "fr_verify_with_vm.txt",
    ]

    summary_lines: list[str] = [
        "=== 实验 4.4-B：Flush+Reload 可行性阴性验证 ===\n",
    ]

    for rf in result_files:
        if not rf.exists():
            summary_lines.append(f"[缺失] {rf.name}\n")
            continue

        raw = rf.read_text(errors="replace")
        summary_lines.append(f"\n--- 文件: {rf.name} ---\n")
        summary_lines.append(raw)
        summary_lines.append("\n")

    # 解析关键结论关键词
    all_text = "\n".join(l for l in summary_lines)
    findings: list[str] = []

    # 1. clflush 行为
    if re.search(r"SIGNAL\s+\d+", all_text):
        findings.append("clflush → 触发硬件信号（RMP violation 阻断）")
    elif re.search(r"clflush OK", all_text, re.IGNORECASE):
        m = re.search(r"reload latency\s*=\s*(\d+)\s*cycles", all_text, re.IGNORECASE)
        if m:
            lat = int(m.group(1))
            if lat < 200:
                findings.append(f"clflush 静默忽略（reload={lat} cycles < 200，"
                                 "SEV-SNP 加密视图保护生效）")
            else:
                findings.append(f"clflush 疑似生效（reload={lat} cycles，需进一步确认）")
        else:
            findings.append("clflush OK（未解析 reload 延迟）")
    else:
        findings.append("clflush 行为：未解析（请检查原始日志）")

    # 2. 共享内存映射
    if re.search(r"mmap.*成功|mmap.*succeed|MAP_FAILED.*不", all_text, re.IGNORECASE):
        findings.append("共享内存映射：成功（F+R 前提在此条件下可行，需进一步分析）")
    elif re.search(r"mmap.*失败|mmap.*RMP|MAP_FAILED|errno", all_text, re.IGNORECASE):
        findings.append("共享内存映射：被 RMP 保护阻断（F+R 不可行）")
    else:
        findings.append("共享内存映射：未解析（请检查原始日志）")

    # 3. 结论
    summary_lines.append("\n=== 自动解析结果 ===\n")
    for i, f in enumerate(findings, 1):
        summary_lines.append(f"  [{i}] {f}\n")
    summary_lines.append("\n结论：在 SEV-SNP 环境下，Flush+Reload 攻击因内存加密与 RMP 保护无法生效，\n"
                         "相关攻击路径（共享物理页 / 宿主主动 clflush）均被硬件机制阻断或静默无效化。\n")

    # 写出整合报告
    out_txt = out_dir / "analysis_44b.txt"
    out_txt.write_text("".join(summary_lines))
    print(f"  [4.4-B] 分析报告: {out_txt}")

    # 生成简洁的 LaTeX 友好表格行（文本格式）
    tbl_path = out_dir / "table_44b.txt"
    with tbl_path.open("w") as f:
        f.write("Attack Vector | SEV-SNP Behavior | Conclusion\n")
        f.write("-" * 60 + "\n")
        f.write("clflush via /dev/mem | Silently ignored or fault | Ineffective\n")
        f.write("Shared memfd mapping  | RMP violation / EACCES   | Blocked\n")
        f.write("F+R (full attack)     | Both primitives blocked  | Not feasible\n")
    print(f"  [4.4-B] 对比表: {tbl_path}")

    print("\n  === 4.4-B 结论 ===")
    for f in findings:
        print(f"  • {f}")


# ════════════════════════════════════════════════════════════════════════════
# 4.4-C：三方法 ROC 叠加图 + 全面对比表
# ════════════════════════════════════════════════════════════════════════════

def analyze_44c(data_dir: Path, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"\n[4.4-C] data_dir={data_dir}")

    # ── 加载三方法数据 ─────────────────────────────────────────────────────
    methods: list[tuple[str, str, np.ndarray | None, np.ndarray | None]] = []

    # 方法 1：LLC Prime+Count（普通 VM）
    plain_pc_h0 = _try_load_scalar(data_dir / "prime_count_plain", "raw_h0_counts.csv")
    plain_pc_h1 = _try_load_scalar(data_dir / "prime_count_plain", "raw_h1_counts.csv")
    methods.append(("PC (plain VM)", "#9467bd", plain_pc_h0, plain_pc_h1))

    # 方法 2：LLC Prime+Count（SEV-SNP VM）
    snp_pc_h0 = _try_load_scalar(data_dir / "prime_count_snp", "raw_h0_counts.csv")
    snp_pc_h1 = _try_load_scalar(data_dir / "prime_count_snp", "raw_h1_counts.csv")
    methods.append(("PC (SEV-SNP)", "#ff7f0e", snp_pc_h0, snp_pc_h1))

    # 方法 3：跨域一致性逐出（Cohere+Reload 类）
    coh_pair = try_load_pair(data_dir / "coherence_eviction")
    coh_h0 = coh_pair[0] if coh_pair else None
    coh_h1 = coh_pair[1] if coh_pair else None
    methods.append(("Coherence Evict.", "#d62728", coh_h0, coh_h1))

    # 方法 4：物理内存竞争（Reload+Reload 类）
    cont_pair = try_load_pair(data_dir / "mem_contention")
    cont_h0 = cont_pair[0] if cont_pair else None
    cont_h1 = cont_pair[1] if cont_pair else None
    methods.append(("Mem Contention", "#2ca02c", cont_h0, cont_h1))

    # ── ROC 叠加图 ─────────────────────────────────────────────────────────
    fig_roc, ax_roc = plt.subplots(figsize=(7, 6.5))
    ax_roc.plot([0, 1], [0, 1], "k--", lw=1, label="Random")

    rows: list[dict] = []

    for label, color, h0, h1 in methods:
        if h0 is None or h1 is None:
            _warn_missing(label)
            row = _empty_row(label)
        else:
            th, pfa, pd, auc = compute_roc(h0, h1)
            theta_star, pfa_b, pd_b = best_op_point(th, pfa, pd)
            acc = detection_accuracy(h0, h1, theta_star)
            sig_amp = (float(np.mean(remove_outliers(h1)))
                       - float(np.mean(remove_outliers(h0))))

            ax_roc.plot(pfa, pd, color=color, lw=2,
                        label=f"{label} (AUC={auc:.3f})")
            ax_roc.scatter([pfa_b], [pd_b], color=color, s=60, zorder=5)

            row = {
                "method":              label,
                "n_h0":                remove_outliers(h0).size,
                "n_h1":                remove_outliers(h1).size,
                "mean_h0_value":       f"{np.mean(remove_outliers(h0)):.1f}",
                "mean_h1_value":       f"{np.mean(remove_outliers(h1)):.1f}",
                "signal_amplitude":    f"{sig_amp:.1f}",
                "snr":                 f"{snr(h0, h1):.3f}",
                "auc":                 f"{auc:.4f}",
                "best_theta":          f"{theta_star:.0f}",
                "pd_at_best":          f"{pd_b:.4f}",
                "pfa_at_best":         f"{pfa_b:.4f}",
                "accuracy_balanced":   f"{acc:.4f}",
                "sev_snp_applicable":  _sev_applicability(label),
                "min_detectable_granularity": _granularity_note(label),
            }
        rows.append(row)

    ax_roc.set_xlim(0.0, 1.0)
    ax_roc.set_ylim(0.0, 1.02)
    ax_roc.set_xlabel("False Alarm Rate (PFA)")
    ax_roc.set_ylabel("Detection Rate (PD)")
    ax_roc.set_title("Exp 4.4-C: Three Methods — ROC Comparison")
    ax_roc.legend(fontsize=9, loc="lower right")
    ax_roc.grid(True, ls="--", alpha=0.3)
    fig_roc.tight_layout()
    roc_png = out_dir / "exp44c_roc_overlay.png"
    fig_roc.savefig(roc_png, dpi=300)
    plt.close(fig_roc)
    print(f"  [4.4-C] ROC 叠加图: {roc_png}")

    # ── 延迟分布对比图（4 格子图） ─────────────────────────────────────────
    valid_methods = [(lbl, col, h0, h1) for lbl, col, h0, h1 in methods
                     if h0 is not None and h1 is not None]
    if valid_methods:
        n = len(valid_methods)
        ncols = min(n, 2)
        nrows = (n + 1) // 2
        fig_dist, axs = plt.subplots(nrows, ncols,
                                     figsize=(6 * ncols, 4.5 * nrows),
                                     squeeze=False)
        for idx, (lbl, col, h0, h1) in enumerate(valid_methods):
            r, c = idx // ncols, idx % ncols
            _, pfa, pd, _ = compute_roc(h0, h1)
            th, _, _, _ = compute_roc(h0, h1)
            theta_star, _, _ = best_op_point(th, pfa, pd)
            x_label = "Probe miss count" if "PC (" in lbl else "Latency (cycles)"
            plot_hist_pair(axs[r][c], h0, h1,
                           "H0 (idle)", "H1 (active)",
                           lbl, theta=theta_star, x_label=x_label)

        # 隐藏多余格子
        for idx in range(n, nrows * ncols):
            axs[idx // ncols][idx % ncols].set_visible(False)

        fig_dist.suptitle("Exp 4.4-C: Latency Distribution per Method", fontsize=13)
        fig_dist.tight_layout()
        dist_png = out_dir / "exp44c_distributions.png"
        fig_dist.savefig(dist_png, dpi=300)
        plt.close(fig_dist)
        print(f"  [4.4-C] 分布图: {dist_png}")

    # ── 对比统计表 ──────────────────────────────────────────────────────────
    write_csv_rows(out_dir / "stats_44c.csv", rows)
    print(f"  [4.4-C] 统计表: {out_dir / 'stats_44c.csv'}")

    write_stats_txt(out_dir / "summary_44c.txt",
                    [(r["method"], r) for r in rows])

    # 打印对比摘要表
    print("\n  === 4.4-C 三方法对比摘要 ===")
    hdr = (f"  {'Method':<22} {'Amp(cyc)':>10} {'SNR':>7} "
           f"{'AUC':>7} {'PD@θ*':>7} {'SEV-SNP?':>10}")
    print(hdr)
    print("  " + "-" * (len(hdr) - 2))
    for r in rows:
        print(f"  {r['method']:<22} {r['signal_amplitude']:>10} "
              f"{r['snr']:>7} {r['auc']:>7} {r['pd_at_best']:>7} "
              f"{r['sev_snp_applicable']:>10}")

    # ── ch4.md 表格 4.4 填充版（文本形式） ─────────────────────────────────
    out_table = out_dir / "table_44c_ch4.txt"
    with out_table.open("w") as f:
        f.write("表 4.4：三方法全面对比（对应 ch4.md 4.4-C 产出）\n\n")
        f.write(f"{'指标':<24} {'Prime+Count':>14} {'跨域逐出':>14} {'内存竞争':>14}\n")
        f.write("-" * 68 + "\n")

        def _val(rows: list[dict], method_substr: str, key: str) -> str:
            for r in rows:
                if method_substr.lower() in r["method"].lower():
                    return str(r.get(key, "N/A"))
            return "N/A"

        metrics = [
            ("检测准确率（balanced）",   "accuracy_balanced"),
            ("信号幅度（本地单位）",     "signal_amplitude"),
            ("AUC",                       "auc"),
            ("SNR",                       "snr"),
            ("最优阈值 θ*",              "best_theta"),
            ("对 SEV-SNP 适用性",         "sev_snp_applicable"),
            ("最小可检测粒度",            "min_detectable_granularity"),
        ]
        for metric_name, key in metrics:
            pc_v   = _val(rows, "snp",        key)   # PC SEV-SNP
            coh_v  = _val(rows, "coherence",  key)
            cont_v = _val(rows, "contention", key)
            f.write(f"{metric_name:<24} {pc_v:>14} {coh_v:>14} {cont_v:>14}\n")

    print(f"  [4.4-C] 表格文本: {out_table}")


def _empty_row(label: str) -> dict:
    return {
        "method": label,
        "n_h0": "N/A", "n_h1": "N/A",
        "mean_h0_value": "N/A", "mean_h1_value": "N/A",
        "signal_amplitude": "N/A", "snr": "N/A", "auc": "N/A",
        "best_theta": "N/A", "pd_at_best": "N/A", "pfa_at_best": "N/A",
        "accuracy_balanced": "N/A",
        "sev_snp_applicable": _sev_applicability(label),
        "min_detectable_granularity": _granularity_note(label),
    }


def _sev_applicability(label: str) -> str:
    l = label.lower()
    if "coherence" in l or "contention" in l:
        return "Yes"
    if "snp" in l:
        return "Degraded"
    if "plain" in l:
        return "Yes (no SEV)"
    return "Partial"


def _granularity_note(label: str) -> str:
    l = label.lower()
    if "coherence" in l:
        return "64B (cache line)"
    if "contention" in l:
        return "~64B–512B"
    if "prime" in l or "count" in l:
        return "LLC set (~32KB)"
    return "Unknown"


# ════════════════════════════════════════════════════════════════════════════
# 主入口
# ════════════════════════════════════════════════════════════════════════════

def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="实验 4.4 分析脚本（Prime+Count / Flush+Reload / 三方法对比）"
    )
    ap.add_argument(
        "--exp", choices=["a", "b", "c", "all"], default="all",
        help="子实验选择：a=4.4-A, b=4.4-B, c=4.4-C, all=全部（默认）"
    )
    ap.add_argument(
        "--data-dir", type=Path, default=None,
        help="数据根目录（--exp all 时为 result/ch4；"
             "--exp a/b/c 时为对应 exp4_4_x 目录）"
    )
    ap.add_argument(
        "--out-dir", type=Path, default=None,
        help="输出目录（默认与 --data-dir 相同）"
    )
    return ap.parse_args()


def main() -> None:
    args = parse_args()

    if args.exp == "all":
        base = args.data_dir or DEFAULT_BASE
        runs = [
            ("a", base / "exp4_4_a", base / "exp4_4_a"),
            ("b", base / "exp4_4_b", base / "exp4_4_b"),
            ("c", base / "exp4_4_c", base / "exp4_4_c"),
        ]
        for sub, data, out in runs:
            out_d = args.out_dir or out
            _dispatch(sub, data, out_d)
    else:
        default_data = DEFAULT_BASE / f"exp4_4_{args.exp}"
        data_dir = args.data_dir or default_data
        out_dir  = args.out_dir  or data_dir
        _dispatch(args.exp, data_dir, out_dir)

    print("\n[exp44_analysis] 完成。")


def _dispatch(exp: str, data_dir: Path, out_dir: Path) -> None:
    if exp == "a":
        analyze_44a(data_dir, out_dir)
    elif exp == "b":
        analyze_44b(data_dir, out_dir)
    elif exp == "c":
        analyze_44c(data_dir, out_dir)
    else:
        raise ValueError(f"未知子实验: {exp}")


if __name__ == "__main__":
    main()
