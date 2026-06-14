#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np


def read_rows(path: Path) -> list[dict[str, float]]:
    rows: list[dict[str, float]] = []
    with path.open(newline="") as f:
        r = csv.DictReader(f)
        for row in r:
            rows.append(
                {
                    "probe_line": float(row["probe_line"]),
                    "h0_mean": float(row["h0_mean"]),
                    "h1_mean": float(row["h1_mean"]),
                    "h0_std": float(row["h0_std"]),
                    "h1_std": float(row["h1_std"]),
                    "delta": float(row["delta"]),
                    "h0_n": float(row["h0_n"]),
                    "h1_n": float(row["h1_n"]),
                }
            )
    return rows


def write_stats(rows: list[dict[str, float]], victim_line: int, out_path: Path) -> None:
    lines = [
        "[4.2-B spatial contention scan]",
        f"victim_line={victim_line}",
        f"n_probe_lines={len(rows)}",
    ]
    if rows:
        best = max(rows, key=lambda r: float(r["delta"]))
        lines += [
            f"best_probe_line={int(best['probe_line'])}",
            f"best_delta={float(best['delta']):.3f}",
            f"victim_delta={next((float(r['delta']) for r in rows if int(r['probe_line']) == victim_line), float('nan')):.3f}",
        ]
    out_path.write_text("\n".join(lines) + "\n")


def plot_delta(rows: list[dict[str, float]], victim_line: int, out_path: Path) -> None:
    xs = np.array([int(r["probe_line"]) for r in rows], dtype=int)
    delta = np.array([float(r["delta"]) for r in rows], dtype=float)

    fig, ax = plt.subplots(figsize=(10.5, 4.8))
    colors = ["crimson" if x == victim_line else "steelblue" for x in xs]
    ax.bar(xs, delta, color=colors, width=0.85)
    ax.axhline(0.0, color="black", linewidth=1.0)
    ax.axvline(victim_line, color="crimson", linestyle="--", linewidth=1.2)
    ax.set_title("4.2-B Spatial Response of Contention Signal")
    ax.set_xlabel("Probe Cache Line Index")
    ax.set_ylabel("Delta = mean(H1) - mean(H0) [cycles]")
    ax.set_xticks(np.arange(0, 64, 4))
    ax.grid(True, axis="y", linestyle=":", alpha=0.5)
    ax.text(victim_line + 0.5, max(delta) * 0.92 if len(delta) else 0.0,
            f"victim_line={victim_line}", color="crimson", fontsize=10)
    fig.tight_layout()
    fig.savefig(out_path, dpi=300)
    plt.close(fig)


def main() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    default_dir = repo_root / "result/ch4/exp4_2_b_spatial"
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=str(default_dir))
    args = ap.parse_args()

    data_dir = Path(args.dir).expanduser().resolve()
    csv_path = data_dir / "spatial_scan.csv"
    meta_path = data_dir / "meta.txt"
    if not csv_path.exists():
        raise SystemExit(f"[!] missing {csv_path}")

    victim_line = 32
    if meta_path.exists():
      for line in meta_path.read_text().splitlines():
        if line.startswith("victim_line="):
          victim_line = int(line.split("=", 1)[1], 0)
          break

    rows = read_rows(csv_path)
    plot_delta(rows, victim_line, data_dir / "exp42b_spatial_delta.png")
    write_stats(rows, victim_line, data_dir / "stats_42b_spatial.txt")
    print(f"[done] {data_dir}")


if __name__ == "__main__":
    main()
