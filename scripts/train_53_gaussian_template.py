#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
from concurrent.futures import ProcessPoolExecutor
import json
import math
import os
import statistics
import time
from pathlib import Path


FINAL_CONTENTION_TEMPLATE_FEATURES = [
    "cont_after_0",
    "cont_after_1",
    "cont_table_top_1",
    "cont_table_top_2",
    "cont_table_top_3",
    "cont_table_top_4",
    "cont_table_top_5",
    "cont_table_top_6",
    "cont_table_top_7",
]


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Train diagonal two-component Gaussian templates from collected Ch5 signal runs.")
    ap.add_argument("--batch-dir", required=True)
    ap.add_argument("--run-prefix", default="run_")
    ap.add_argument("--max-runs", type=int, default=0)
    ap.add_argument("--byte-pos", type=int, default=-1, help="Optional byte position filter.")
    ap.add_argument("--roles", default=",".join(FINAL_CONTENTION_TEMPLATE_FEATURES))
    ap.add_argument("--step", type=int, default=8, help="d-range scan step in cycles.")
    ap.add_argument(
        "--drange-widths",
        default="64,128,256,512",
        help="Comma-separated candidate d-range widths in cycles.",
    )
    ap.add_argument(
        "--drange-lo-pctl-min",
        type=float,
        default=5.0,
        help="Lower percentile bound for candidate d_lo search.",
    )
    ap.add_argument(
        "--drange-lo-pctl-max",
        type=float,
        default=95.0,
        help="Upper percentile bound for candidate d_lo search.",
    )
    ap.add_argument("--max-em-iters", type=int, default=20)
    ap.add_argument("--jobs", type=int, default=0, help="Worker processes. 0 means os.cpu_count().")
    ap.add_argument("--progress-every", type=int, default=16, help="Print progress every N completed tasks.")
    ap.add_argument(
        "--drange-progress-every",
        type=int,
        default=16,
        help="Print infer_drange internal progress every N lower-bound steps.",
    )
    ap.add_argument("--out-json", default="")
    return ap.parse_args()


def load_json(path: Path) -> dict:
    return json.loads(path.read_text())


def rrmb_count(vals: list[float], d_lo: float, d_hi: float) -> int:
    return sum(1 for x in vals if float(d_lo) <= float(x) < float(d_hi))


def build_prefix_from_burst(vals: list[float], step: int, num_bins: int) -> list[int]:
    hist = [0] * num_bins
    step_f = float(step)
    for x in vals:
        idx = int(float(x) // step_f)
        if idx < 0:
            idx = 0
        elif idx >= num_bins:
            idx = num_bins - 1
        hist[idx] += 1
    pref = [0] * (num_bins + 1)
    acc = 0
    for i, c in enumerate(hist, start=1):
        acc += c
        pref[i] = acc
    return pref


def percentile(sorted_vals: list[float], q: float) -> float:
    if not sorted_vals:
        return 0.0
    if q <= 0.0:
        return float(sorted_vals[0])
    if q >= 100.0:
        return float(sorted_vals[-1])
    pos = (len(sorted_vals) - 1) * (q / 100.0)
    lo = int(math.floor(pos))
    hi = int(math.ceil(pos))
    if lo == hi:
        return float(sorted_vals[lo])
    frac = pos - lo
    return float(sorted_vals[lo] * (1.0 - frac) + sorted_vals[hi] * frac)


def infer_drange(
    entry_to_bursts: dict[int, list[list[float]]],
    step: int,
    *,
    role_label: str = "",
    progress_every: int = 0,
    widths: list[int] | None = None,
    lo_pctl_min: float = 5.0,
    lo_pctl_max: float = 95.0,
) -> dict[str, float]:
    all_lats: list[float] = []
    for bursts in entry_to_bursts.values():
        for xs in bursts:
            all_lats.extend(float(x) for x in xs)
    if not all_lats:
        return {"d_lo": 0.0, "d_hi": float(step), "score": 0.0}
    all_lats_sorted = sorted(all_lats)
    ub = (int(max(all_lats_sorted)) // int(step) + 2) * int(step)
    if not widths:
        widths = [64, 128, 256, 512]
    widths = sorted(set(max(int(step), int(w)) for w in widths))
    num_bins = max(1, ub // int(step))
    pref_by_entry: dict[int, list[list[int]]] = {}
    for e, bursts in entry_to_bursts.items():
        pref_by_entry[int(e)] = [build_prefix_from_burst(xs, int(step), num_bins) for xs in bursts]
    best = {"d_lo": 0.0, "d_hi": float(ub), "score": -1.0}
    lo_min = int(percentile(all_lats_sorted, float(lo_pctl_min)) // int(step)) * int(step)
    lo_max = int(percentile(all_lats_sorted, float(lo_pctl_max)) // int(step)) * int(step)
    lo_min = max(0, min(lo_min, ub - int(step)))
    lo_max = max(lo_min + int(step), min(lo_max, ub))
    lo_values = list(range(lo_min, max(lo_min + int(step), lo_max), int(step)))
    total_lo = len(lo_values)
    for idx_lo, lo in enumerate(lo_values, start=1):
        if progress_every > 0 and (idx_lo % progress_every == 0 or idx_lo == total_lo):
            prefix = f"[train-gmm][{role_label}]" if role_label else "[train-gmm]"
            print(
                f"{prefix} infer_drange lo-step {idx_lo}/{total_lo} ({idx_lo/max(1,total_lo):.1%})",
                flush=True,
            )
        for width in widths:
            hi = min(ub, lo + int(width))
            if hi <= lo:
                continue
            lo_idx = int(lo // int(step))
            hi_idx = min(num_bins, int(hi // int(step)))
            centers: list[float] = []
            within: list[float] = []
            overall_mean: list[float] = []
            for e, pref_list in pref_by_entry.items():
                counts = [int(pref[hi_idx] - pref[lo_idx]) for pref in pref_list]
                if not counts:
                    continue
                mu = float(statistics.fmean(counts))
                centers.append(mu)
                overall_mean.append(mu)
                if len(counts) > 1:
                    within.append(float(statistics.pvariance(counts)))
            if len(centers) < 2:
                continue
            between = float(statistics.pvariance(centers))
            within_mean = float(statistics.fmean(within)) if within else 1.0
            mean_level = float(statistics.fmean(overall_mean)) if overall_mean else 0.0
            saturation_penalty = 1.0 + max(0.0, mean_level - 0.75 * 16.0)
            score = between / (max(1.0, within_mean) * saturation_penalty)
            if score > float(best["score"]):
                best = {"d_lo": float(lo), "d_hi": float(hi), "score": float(score)}
    prefix = f"[train-gmm][{role_label}]" if role_label else "[train-gmm]"
    print(
        f"{prefix} infer_drange done d_lo={best['d_lo']:.0f} d_hi={best['d_hi']:.0f} score={best['score']:.4f}",
        flush=True,
    )
    return best


def infer_drange_worker(payload: tuple[str, dict[int, list[list[float]]], int, int, list[int], float, float]) -> tuple[str, dict[str, float]]:
    role, entry_to_bursts, step, progress_every, widths, lo_pctl_min, lo_pctl_max = payload
    print(f"[train-gmm][{role}] infer_drange start", flush=True)
    return role, infer_drange(
        entry_to_bursts,
        step,
        role_label=role,
        progress_every=progress_every,
        widths=widths,
        lo_pctl_min=lo_pctl_min,
        lo_pctl_max=lo_pctl_max,
    )


def parse_signal_run(run_dir: Path) -> dict:
    meta = load_json(run_dir / "signal_meta.json")
    role_specs = {str(r["name"]): int(r["line"]) for r in meta["role_specs"]}
    rows: list[dict] = []
    with (run_dir / "signal_observations.csv").open() as fp:
        rd = csv.DictReader(fp)
        for row in rd:
            bursts_raw = json.loads(row["line_scores_cont_burst_json"])
            rows.append(
                {
                    "entry": int(row["entry"]),
                    "pt_byte": int(row["pt_byte"]),
                    "bursts_by_line": {int(k): [float(x) for x in v] for k, v in bursts_raw.items()},
                }
            )
    return {
        "name": run_dir.name,
        "byte_pos": int(meta["byte_pos"]),
        "role_specs": role_specs,
        "rows": rows,
    }


def build_feature_vector(row: dict, roles: list[str], role_specs: dict[str, int], drange_meta: dict[str, dict[str, float]]) -> list[float]:
    role_counts: dict[str, float] = {}
    for role in roles:
        base_role = role.replace("cont_", "")
        if base_role not in role_specs:
            continue
        line = int(role_specs[base_role])
        bursts = row["bursts_by_line"].get(line, [])
        meta = drange_meta[role]
        role_counts[role] = float(rrmb_count(bursts, meta["d_lo"], meta["d_hi"]))
    vec = [role_counts.get(r, 0.0) for r in roles]
    if "cont_after_0" in role_counts or "cont_after_1" in role_counts:
        after_vals = [role_counts.get("cont_after_0", 0.0), role_counts.get("cont_after_1", 0.0)]
        vec.append(max(after_vals))
        vec.append(sum(after_vals))
    return vec


def kmeans_init(X: list[list[float]]) -> tuple[list[float], list[float]]:
    sums = [sum(x) for x in X]
    i_min = min(range(len(X)), key=lambda i: sums[i])
    i_max = max(range(len(X)), key=lambda i: sums[i])
    return list(X[i_min]), list(X[i_max])


def fit_diag_gmm2(X: list[list[float]], max_iters: int = 20) -> list[dict[str, object]]:
    if not X:
        return []
    if len(X) == 1:
        x = list(X[0])
        return [
            {"weight": 1.0, "mean": x, "var": [1.0 for _ in x]},
            {"weight": 0.0, "mean": x, "var": [1.0 for _ in x]},
        ]
    n = len(X)
    d = len(X[0])
    mu0, mu1 = kmeans_init(X)
    var0 = [100.0] * d
    var1 = [100.0] * d
    w0 = 0.5
    w1 = 0.5
    for _ in range(max_iters):
        resp0: list[float] = []
        resp1: list[float] = []
        for x in X:
            l0 = math.log(max(1e-9, w0)) + sum(
                -0.5 * (math.log(2.0 * math.pi * max(1e-9, var0[j])) + ((x[j] - mu0[j]) ** 2) / max(1e-9, var0[j]))
                for j in range(d)
            )
            l1 = math.log(max(1e-9, w1)) + sum(
                -0.5 * (math.log(2.0 * math.pi * max(1e-9, var1[j])) + ((x[j] - mu1[j]) ** 2) / max(1e-9, var1[j]))
                for j in range(d)
            )
            m = max(l0, l1)
            p0 = math.exp(l0 - m)
            p1 = math.exp(l1 - m)
            z = max(1e-9, p0 + p1)
            resp0.append(p0 / z)
            resp1.append(p1 / z)
        n0 = max(1e-6, sum(resp0))
        n1 = max(1e-6, sum(resp1))
        w0 = n0 / n
        w1 = n1 / n
        mu0 = [sum(resp0[i] * X[i][j] for i in range(n)) / n0 for j in range(d)]
        mu1 = [sum(resp1[i] * X[i][j] for i in range(n)) / n1 for j in range(d)]
        var0 = [max(1.0, sum(resp0[i] * (X[i][j] - mu0[j]) ** 2 for i in range(n)) / n0) for j in range(d)]
        var1 = [max(1.0, sum(resp1[i] * (X[i][j] - mu1[j]) ** 2 for i in range(n)) / n1) for j in range(d)]
    return [
        {"weight": float(w0), "mean": [float(x) for x in mu0], "var": [float(x) for x in var0]},
        {"weight": float(w1), "mean": [float(x) for x in mu1], "var": [float(x) for x in var1]},
    ]


def fit_entry_worker(payload: tuple[int, list[list[float]], int]) -> tuple[int, dict[str, object] | None]:
    entry, X, max_em_iters = payload
    if not X:
        return entry, None
    return entry, {
        "components": fit_diag_gmm2(X, max_iters=max_em_iters),
        "n": int(len(X)),
    }


def main() -> None:
    args = parse_args()
    batch_dir = Path(args.batch_dir).resolve()
    out_json = Path(args.out_json).resolve() if args.out_json else batch_dir / "gaussian_template_model.json"
    roles = [x.strip() for x in str(args.roles).split(",") if x.strip()]
    drange_widths = [int(x.strip()) for x in str(args.drange_widths).split(",") if x.strip()]
    jobs = int(args.jobs) if int(args.jobs) > 0 else int(os.cpu_count() or 1)
    progress_every = max(1, int(args.progress_every))
    drange_progress_every = max(1, int(args.drange_progress_every))

    run_dirs = sorted([p for p in batch_dir.iterdir() if p.is_dir() and p.name.startswith(args.run_prefix)])
    if args.max_runs > 0:
        run_dirs = run_dirs[: int(args.max_runs)]
    runs = [parse_signal_run(p) for p in run_dirs]
    if args.byte_pos >= 0:
        runs = [r for r in runs if int(r["byte_pos"]) == int(args.byte_pos)]
    if not runs:
        raise SystemExit("no signal runs found")

    byte_pos = int(runs[0]["byte_pos"])
    role_specs = runs[0]["role_specs"]

    entry_role_bursts: dict[str, dict[int, list[list[float]]]] = {role: {} for role in roles}
    for run in runs:
        for row in run["rows"]:
            entry = int(row["entry"])
            for role in roles:
                base_role = role.replace("cont_", "")
                if base_role not in role_specs:
                    continue
                line = int(role_specs[base_role])
                entry_role_bursts[role].setdefault(entry, []).append(row["bursts_by_line"].get(line, []))

    drange_meta: dict[str, dict[str, float]] = {}
    start = time.time()
    role_payloads = [
        (
            role,
            entry_role_bursts[role],
            int(args.step),
            drange_progress_every,
            drange_widths,
            float(args.drange_lo_pctl_min),
            float(args.drange_lo_pctl_max),
        )
        for role in roles
    ]
    done = 0
    total = len(role_payloads)
    if jobs <= 1:
        for payload in role_payloads:
            role, meta = infer_drange_worker(payload)
            drange_meta[role] = meta
            done += 1
            if done % progress_every == 0 or done == total:
                elapsed = max(0.001, time.time() - start)
                rate = done / elapsed
                eta = (total - done) / max(1e-9, rate)
                print(f"[train-gmm] d-range {done}/{total} ({done/total:.1%}) rate={rate:.2f}/s eta={eta:.1f}s", flush=True)
    else:
        with ProcessPoolExecutor(max_workers=jobs) as ex:
            for role, meta in ex.map(infer_drange_worker, role_payloads, chunksize=1):
                drange_meta[role] = meta
                done += 1
                if done % progress_every == 0 or done == total:
                    elapsed = max(0.001, time.time() - start)
                    rate = done / elapsed
                    eta = (total - done) / max(1e-9, rate)
                    print(f"[train-gmm] d-range {done}/{total} ({done/total:.1%}) rate={rate:.2f}/s eta={eta:.1f}s", flush=True)

    entry_models: dict[str, dict[str, object]] = {}
    feature_headers = list(roles)
    if "cont_after_0" in roles or "cont_after_1" in roles:
        feature_headers.append("cont_after_max")
        feature_headers.append("cont_after_sum")

    entry_payloads: list[tuple[int, list[list[float]], int]] = []
    for entry in range(256):
        X: list[list[float]] = []
        for run in runs:
            for row in run["rows"]:
                if int(row["entry"]) != entry:
                    continue
                X.append(build_feature_vector(row, roles, role_specs, drange_meta))
        entry_payloads.append((entry, X, int(args.max_em_iters)))

    start = time.time()
    done = 0
    total = len(entry_payloads)
    if jobs <= 1:
        for payload in entry_payloads:
            entry, model_obj = fit_entry_worker(payload)
            if model_obj is not None:
                entry_models[str(entry)] = model_obj
            done += 1
            if done % progress_every == 0 or done == total:
                elapsed = max(0.001, time.time() - start)
                rate = done / elapsed
                eta = (total - done) / max(1e-9, rate)
                print(f"[train-gmm] entries {done}/{total} ({done/total:.1%}) rate={rate:.2f}/s eta={eta:.1f}s", flush=True)
    else:
        with ProcessPoolExecutor(max_workers=jobs) as ex:
            for entry, model_obj in ex.map(fit_entry_worker, entry_payloads, chunksize=1):
                if model_obj is not None:
                    entry_models[str(entry)] = model_obj
                done += 1
                if done % progress_every == 0 or done == total:
                    elapsed = max(0.001, time.time() - start)
                    rate = done / elapsed
                    eta = (total - done) / max(1e-9, rate)
                    print(f"[train-gmm] entries {done}/{total} ({done/total:.1%}) rate={rate:.2f}/s eta={eta:.1f}s", flush=True)

    model = {
        "model_type": "rrmb_gmm_diagonal",
        "source_batch_dir": str(batch_dir),
        "jobs": int(jobs),
        "bytes": [
            {
                "byte_pos": int(byte_pos),
                "feature_headers": feature_headers,
                "role_specs": [{"name": k, "line": int(v)} for k, v in role_specs.items()],
                "drange_meta": drange_meta,
                "entries": entry_models,
            }
        ],
    }
    out_json.write_text(json.dumps(model, indent=2, ensure_ascii=False) + "\n")
    print(f"[train-gmm] wrote {out_json}", flush=True)


if __name__ == "__main__":
    main()
