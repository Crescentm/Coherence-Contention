#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import math
import os
import pickle
import statistics
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path


DEFAULT_ROLES = [
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
    ap = argparse.ArgumentParser(
        description="Train a RRMB count + role-feature tree classifier for AES byte recovery."
    )
    ap.add_argument("--batch-dir", required=True)
    ap.add_argument("--run-prefix", default="run_")
    ap.add_argument("--max-runs", type=int, default=0)
    ap.add_argument("--byte-pos", type=int, default=0)
    ap.add_argument("--backend", default="auto", choices=["auto", "lightgbm", "xgboost"])
    ap.add_argument("--roles", default=",".join(DEFAULT_ROLES))
    ap.add_argument("--step", type=int, default=8)
    ap.add_argument("--drange-widths", default="64,128,256,512")
    ap.add_argument("--drange-lo-pctl-min", type=float, default=5.0)
    ap.add_argument("--drange-lo-pctl-max", type=float, default=95.0)
    ap.add_argument("--jobs", type=int, default=0)
    ap.add_argument("--progress-every", type=int, default=4)
    ap.add_argument("--n-estimators", type=int, default=300)
    ap.add_argument("--max-depth", type=int, default=6)
    ap.add_argument("--learning-rate", type=float, default=0.05)
    ap.add_argument("--subsample", type=float, default=0.8)
    ap.add_argument("--colsample-bytree", type=float, default=0.8)
    ap.add_argument("--eval-loro", action="store_true")
    ap.add_argument("--top-k", type=int, default=20)
    ap.add_argument("--outdir", default="")
    return ap.parse_args()


def load_json(path: Path) -> dict:
    return json.loads(path.read_text())


def rrmb_count(vals: list[float], d_lo: float, d_hi: float) -> int:
    return sum(1 for x in vals if float(d_lo) <= float(x) < float(d_hi))


def build_prefix(vals: list[float], step: int, num_bins: int) -> list[int]:
    hist = [0] * num_bins
    for x in vals:
        idx = int(float(x) // float(step))
        if idx < 0:
            idx = 0
        elif idx >= num_bins:
            idx = num_bins - 1
        hist[idx] += 1
    pref = [0] * (num_bins + 1)
    s = 0
    for i, c in enumerate(hist, start=1):
        s += c
        pref[i] = s
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
    *,
    step: int,
    widths: list[int],
    lo_pctl_min: float,
    lo_pctl_max: float,
) -> dict[str, float]:
    all_lats: list[float] = []
    for bursts in entry_to_bursts.values():
        for xs in bursts:
            all_lats.extend(float(x) for x in xs)
    if not all_lats:
        return {"d_lo": 0.0, "d_hi": float(step), "score": 0.0}
    all_lats.sort()
    ub = (int(max(all_lats)) // int(step) + 2) * int(step)
    num_bins = max(1, ub // int(step))
    pref_by_entry = {
        int(e): [build_prefix(xs, int(step), num_bins) for xs in bursts]
        for e, bursts in entry_to_bursts.items()
    }
    lo_min = int(percentile(all_lats, float(lo_pctl_min)) // int(step)) * int(step)
    lo_max = int(percentile(all_lats, float(lo_pctl_max)) // int(step)) * int(step)
    lo_min = max(0, min(lo_min, ub - int(step)))
    lo_max = max(lo_min + int(step), min(lo_max, ub))
    lo_values = list(range(lo_min, max(lo_min + int(step), lo_max), int(step)))
    best = {"d_lo": 0.0, "d_hi": float(ub), "score": -1.0}
    for lo in lo_values:
        for width in widths:
            hi = min(ub, lo + int(width))
            if hi <= lo:
                continue
            lo_idx = int(lo // int(step))
            hi_idx = min(num_bins, int(hi // int(step)))
            centers: list[float] = []
            within: list[float] = []
            overall: list[float] = []
            for e, pref_list in pref_by_entry.items():
                counts = [int(pref[hi_idx] - pref[lo_idx]) for pref in pref_list]
                if not counts:
                    continue
                mu = float(statistics.fmean(counts))
                centers.append(mu)
                overall.append(mu)
                if len(counts) > 1:
                    within.append(float(statistics.pvariance(counts)))
            if len(centers) < 2:
                continue
            between = float(statistics.pvariance(centers))
            within_mean = float(statistics.fmean(within)) if within else 1.0
            mean_level = float(statistics.fmean(overall)) if overall else 0.0
            saturation_penalty = 1.0 + max(0.0, mean_level - 12.0)
            score = between / (max(1.0, within_mean) * saturation_penalty)
            if score > float(best["score"]):
                best = {"d_lo": float(lo), "d_hi": float(hi), "score": float(score)}
    return best


def infer_drange_worker(payload: tuple[str, dict[int, list[list[float]]], int, list[int], float, float]) -> tuple[str, dict[str, float]]:
    role, entry_to_bursts, step, widths, lo_pctl_min, lo_pctl_max = payload
    return role, infer_drange(
        entry_to_bursts,
        step=int(step),
        widths=widths,
        lo_pctl_min=float(lo_pctl_min),
        lo_pctl_max=float(lo_pctl_max),
    )


def load_run(run_dir: Path) -> dict:
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
        "true_key_hex": meta.get("true_key_hex", ""),
    }


def resolve_backend(name: str):
    if name in ("auto", "lightgbm"):
        try:
            import lightgbm as lgb  # type: ignore
            return "lightgbm", lgb
        except Exception:
            if name == "lightgbm":
                raise
    if name in ("auto", "xgboost"):
        try:
            import xgboost as xgb  # type: ignore
            return "xgboost", xgb
        except Exception:
            if name == "xgboost":
                raise
    raise SystemExit("Neither lightgbm nor xgboost is available in this Python environment.")


def build_features_for_row(row: dict, roles: list[str], role_specs: dict[str, int], drange_meta: dict[str, dict[str, float]]) -> list[float]:
    role_counts: dict[str, float] = {}
    for role in roles:
        base = role.replace("cont_", "")
        if base not in role_specs:
            continue
        line = int(role_specs[base])
        bursts = row["bursts_by_line"].get(line, [])
        meta = drange_meta[role]
        role_counts[role] = float(rrmb_count(bursts, meta["d_lo"], meta["d_hi"]))
    vec = [role_counts.get(r, 0.0) for r in roles]
    if "cont_after_0" in roles or "cont_after_1" in roles:
        after_vals = [role_counts.get("cont_after_0", 0.0), role_counts.get("cont_after_1", 0.0)]
        vec.append(max(after_vals))
        vec.append(sum(after_vals))
    return vec


def fit_model(backend_name: str, backend_mod, X: list[list[float]], y: list[int], args: argparse.Namespace):
    if backend_name == "lightgbm":
        clf = backend_mod.LGBMClassifier(
            objective="multiclass",
            num_class=256,
            n_estimators=int(args.n_estimators),
            max_depth=int(args.max_depth),
            learning_rate=float(args.learning_rate),
            subsample=float(args.subsample),
            colsample_bytree=float(args.colsample_bytree),
            n_jobs=int(args.jobs) if int(args.jobs) > 0 else -1,
            verbose=-1,
        )
        clf.fit(X, y)
        return clf
    clf = backend_mod.XGBClassifier(
        objective="multi:softprob",
        num_class=256,
        n_estimators=int(args.n_estimators),
        max_depth=int(args.max_depth),
        learning_rate=float(args.learning_rate),
        subsample=float(args.subsample),
        colsample_bytree=float(args.colsample_bytree),
        n_jobs=int(args.jobs) if int(args.jobs) > 0 else 1,
        eval_metric="mlogloss",
        tree_method="hist",
    )
    clf.fit(X, y)
    return clf


def score_key_ranking(proba_rows: list[list[float]], pt_bytes: list[int]) -> list[dict[str, float | int]]:
    ranking: list[dict[str, float | int]] = []
    for k in range(256):
        total = 0.0
        for probs, ptb in zip(proba_rows, pt_bytes):
            entry = int(ptb) ^ int(k)
            p = max(1e-12, float(probs[entry]))
            total += math.log(p)
        ranking.append({"key": int(k), "score": float(total)})
    ranking.sort(key=lambda r: float(r["score"]), reverse=True)
    return ranking


def evaluate_loro(runs: list[dict], roles: list[str], drange_meta: dict[str, dict[str, float]], backend_name: str, backend_mod, args: argparse.Namespace, true_key: int) -> list[dict]:
    rows = []
    for i, test_run in enumerate(runs):
        train_runs = [r for j, r in enumerate(runs) if j != i]
        X_train, y_train = [], []
        for r in train_runs:
            for row in r["rows"]:
                X_train.append(build_features_for_row(row, roles, r["role_specs"], drange_meta))
                y_train.append(int(row["entry"]))
        clf = fit_model(backend_name, backend_mod, X_train, y_train, args)
        X_test = [build_features_for_row(row, roles, test_run["role_specs"], drange_meta) for row in test_run["rows"]]
        pt_bytes = [int(row["pt_byte"]) for row in test_run["rows"]]
        proba = clf.predict_proba(X_test)
        ranking = score_key_ranking(proba.tolist() if hasattr(proba, "tolist") else proba, pt_bytes)
        true_rank = next((idx for idx, row in enumerate(ranking, start=1) if int(row["key"]) == int(true_key)), 0)
        rows.append(
            {
                "run": test_run["name"],
                "best_key": int(ranking[0]["key"]),
                "true_rank": int(true_rank),
            }
        )
    return rows


def main() -> None:
    args = parse_args()
    batch_dir = Path(args.batch_dir).resolve()
    outdir = Path(args.outdir).resolve() if args.outdir else batch_dir / "tree_model"
    outdir.mkdir(parents=True, exist_ok=True)
    roles = [x.strip() for x in str(args.roles).split(",") if x.strip()]
    widths = [int(x.strip()) for x in str(args.drange_widths).split(",") if x.strip()]
    jobs = int(args.jobs) if int(args.jobs) > 0 else int(os.cpu_count() or 1)
    backend_name, backend_mod = resolve_backend(str(args.backend))

    run_dirs = sorted([p for p in batch_dir.iterdir() if p.is_dir() and p.name.startswith(args.run_prefix)])
    if args.max_runs > 0:
        run_dirs = run_dirs[: int(args.max_runs)]
    runs = [load_run(p) for p in run_dirs]
    if args.byte_pos >= 0:
        runs = [r for r in runs if int(r["byte_pos"]) == int(args.byte_pos)]
    if not runs:
        raise SystemExit("no signal runs found")

    byte_pos = int(runs[0]["byte_pos"])
    true_key = int(runs[0]["true_key_hex"][:2], 16) if runs[0].get("true_key_hex") else 0x5A

    entry_role_bursts = {role: {} for role in roles}
    for run in runs:
        for row in run["rows"]:
            entry = int(row["entry"])
            for role in roles:
                base = role.replace("cont_", "")
                if base not in run["role_specs"]:
                    continue
                line = int(run["role_specs"][base])
                entry_role_bursts[role].setdefault(entry, []).append(row["bursts_by_line"].get(line, []))

    payloads = [(role, entry_role_bursts[role], int(args.step), widths, float(args.drange_lo_pctl_min), float(args.drange_lo_pctl_max)) for role in roles]
    drange_meta = {}
    with ProcessPoolExecutor(max_workers=jobs) as ex:
        for role, meta in ex.map(infer_drange_worker, payloads, chunksize=1):
            drange_meta[role] = meta

    X, y = [], []
    for run in runs:
        for row in run["rows"]:
            X.append(build_features_for_row(row, roles, run["role_specs"], drange_meta))
            y.append(int(row["entry"]))
    clf = fit_model(backend_name, backend_mod, X, y, args)

    model_pkl = outdir / "tree_model.pkl"
    with model_pkl.open("wb") as fp:
        pickle.dump(clf, fp)

    meta = {
        "backend": backend_name,
        "byte_pos": int(byte_pos),
        "roles": roles,
        "feature_headers": list(roles) + ["cont_after_max", "cont_after_sum"],
        "drange_meta": drange_meta,
        "true_key_hex": f"{true_key:02x}",
        "model_pkl": str(model_pkl),
    }
    write_path = outdir / "tree_model_meta.json"
    write_path.write_text(json.dumps(meta, indent=2, ensure_ascii=False) + "\n")

    if args.eval_loro:
        rows = evaluate_loro(runs, roles, drange_meta, backend_name, backend_mod, args, true_key)
        with (outdir / "tree_loro_summary.csv").open("w", newline="") as fp:
            wr = csv.writer(fp)
            wr.writerow(["run", "best_key", "true_rank"])
            for row in rows:
                wr.writerow([row["run"], f"0x{int(row['best_key']):02x}", int(row["true_rank"])])
        (outdir / "tree_loro_summary.json").write_text(json.dumps({"rows": rows}, indent=2, ensure_ascii=False) + "\n")

    print(f"[train-tree] backend={backend_name} wrote {model_pkl}")
    print(f"[train-tree] wrote {write_path}")


if __name__ == "__main__":
    main()
