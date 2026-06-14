#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import math
import pickle
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Online partial-byte recovery using an offline-trained RRMB tree classifier."
    )
    ap.add_argument("--model-dir", required=True, help="Directory containing tree_model.pkl and tree_model_meta.json")
    ap.add_argument("--observations-csv", required=True, help="signal_observations.csv from run_53_online_signal_collect.py")
    ap.add_argument("--byte-positions", default="0")
    ap.add_argument("--top-k", type=int, default=16)
    ap.add_argument("--true-key-hex", default="")
    ap.add_argument("--outdir", default="")
    return ap.parse_args()


def parse_byte_positions(raw: str) -> list[int]:
    vals: list[int] = []
    for tok in str(raw).split(","):
        tok = tok.strip()
        if not tok:
            continue
        v = int(tok, 0)
        if 0 <= v <= 15:
            vals.append(v)
    out = sorted(set(vals))
    if not out:
        raise SystemExit("no valid byte positions")
    return out


def load_json(path: Path) -> dict:
    return json.loads(path.read_text())


def rrmb_count(vals: list[float], d_lo: float, d_hi: float) -> int:
    return sum(1 for x in vals if float(d_lo) <= float(x) < float(d_hi))


def load_observations(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open() as fp:
        rd = csv.DictReader(fp)
        for row in rd:
            bursts = json.loads(row["line_scores_cont_burst_json"])
            rows.append(
                {
                    "sample_id": int(row["sample_id"]),
                    "pt": bytes.fromhex(str(row["pt_hex"])),
                    "pt_byte": int(row["pt_byte"]),
                    "bursts_by_line": {int(k): [float(x) for x in v] for k, v in bursts.items()},
                }
            )
    return rows


def feature_vector(obs: dict[str, Any], role_specs: dict[str, int], feature_headers: list[str], drange_meta: dict[str, dict[str, float]]) -> list[float]:
    role_counts: dict[str, float] = {}
    for role_name, line in role_specs.items():
        key = f"cont_{role_name}"
        if key not in drange_meta:
            continue
        meta = drange_meta[key]
        bursts = obs["bursts_by_line"].get(int(line), [])
        role_counts[key] = float(rrmb_count(bursts, meta["d_lo"], meta["d_hi"]))
    vec: list[float] = []
    for feat in feature_headers:
        if feat in role_counts:
            vec.append(float(role_counts[feat]))
        elif feat == "cont_after_max":
            vec.append(max(role_counts.get("cont_after_0", 0.0), role_counts.get("cont_after_1", 0.0)))
        elif feat == "cont_after_sum":
            vec.append(float(role_counts.get("cont_after_0", 0.0) + role_counts.get("cont_after_1", 0.0)))
        else:
            vec.append(0.0)
    return vec


def score_key_ranking(proba_rows: list[list[float]], pt_bytes: list[int]) -> list[dict[str, Any]]:
    ranking: list[dict[str, Any]] = []
    for key_guess in range(256):
        total = 0.0
        for probs, ptb in zip(proba_rows, pt_bytes):
            entry = int(ptb) ^ int(key_guess)
            p = max(1e-12, float(probs[entry]))
            total += math.log(p)
        ranking.append(
            {
                "key": int(key_guess),
                "score": float(total),
                "avg_score": float(total / max(1, len(pt_bytes))),
                "valid_samples": int(len(pt_bytes)),
            }
        )
    ranking.sort(key=lambda r: (float(r["score"]), float(r["avg_score"])), reverse=True)
    return ranking


def write_feature_contrib(
    outdir: Path,
    byte_pos: int,
    feature_headers: list[str],
    obs_features: list[list[float]],
    best_probs: list[list[float]],
    runner_probs: list[list[float]],
    best_key: int,
    runner_key: int,
) -> None:
    sums_best = [0.0 for _ in feature_headers]
    sums_runner = [0.0 for _ in feature_headers]
    # Tree models do not expose clean per-feature log-probability terms; use SHAP-like proxy via feature means weighted by score gap.
    # For thesis-oriented diagnostics, report feature mean values alongside total class log-probability gap.
    if not obs_features:
        return
    n = float(len(obs_features))
    for vec in obs_features:
        for i, val in enumerate(vec):
            sums_best[i] += float(val)
            sums_runner[i] += float(val)
    path = outdir / f"byte_{byte_pos:02d}_feature_contrib.csv"
    gap_total = 0.0
    for bp, rp in zip(best_probs, runner_probs):
        gap_total += math.log(max(1e-12, float(bp[best_key]))) - math.log(max(1e-12, float(rp[runner_key])))
    with path.open("w", newline="") as fp:
        wr = csv.writer(fp)
        wr.writerow(["feature", "best_key", "runner_up", "mean_value", "global_gap_note"])
        for feat, s in zip(feature_headers, sums_best):
            wr.writerow([feat, f"0x{best_key:02x}", f"0x{runner_key:02x}", f"{float(s / n):.6f}", "tree model uses global class probability, not additive per-feature likelihood"])
        wr.writerow(["total_logprob_gap", f"0x{best_key:02x}", f"0x{runner_key:02x}", "", f"{gap_total:.6f}"])


def write_rankings(outdir: Path, byte_pos: int, ranking: list[dict[str, Any]], top_k: int) -> None:
    with (outdir / f"byte_{byte_pos:02d}_ranking.csv").open("w", newline="") as fp:
        wr = csv.writer(fp)
        wr.writerow(["rank", "key", "score", "avg_score", "valid_samples"])
        for idx, row in enumerate(ranking[: max(1, int(top_k))], start=1):
            wr.writerow([idx, f"0x{int(row['key']):02x}", f"{float(row['score']):.6f}", f"{float(row['avg_score']):.6f}", int(row["valid_samples"])])


def main() -> None:
    args = parse_args()
    model_dir = Path(args.model_dir).resolve()
    meta = load_json(model_dir / "tree_model_meta.json")
    with (model_dir / "tree_model.pkl").open("rb") as fp:
        clf = pickle.load(fp)

    observations = load_observations(Path(args.observations_csv).resolve())
    outdir = Path(args.outdir).resolve() if args.outdir else Path.cwd() / "tree_online_recovery"
    outdir.mkdir(parents=True, exist_ok=True)
    byte_positions = parse_byte_positions(args.byte_positions)
    true_key = bytes.fromhex(str(args.true_key_hex).strip()) if str(args.true_key_hex).strip() else None

    model_byte_pos = int(meta["byte_pos"])
    if any(int(bp) != model_byte_pos for bp in byte_positions):
        raise SystemExit(f"tree model only supports byte_pos={model_byte_pos}, got {byte_positions}")

    obs_meta = load_json(Path(args.observations_csv).resolve().parent / "signal_meta.json")
    role_specs = {str(x["name"]): int(x["line"]) for x in obs_meta["role_specs"]}
    feature_headers = [str(x) for x in meta["feature_headers"]]
    drange_meta = {str(k): {"d_lo": float(v["d_lo"]), "d_hi": float(v["d_hi"])} for k, v in meta["drange_meta"].items()}

    rows: list[dict[str, Any]] = []
    for byte_pos in byte_positions:
        X = [feature_vector(obs, role_specs, feature_headers, drange_meta) for obs in observations]
        pt_bytes = [int(obs["pt"][byte_pos]) for obs in observations]
        proba = clf.predict_proba(X)
        proba_rows = proba.tolist() if hasattr(proba, "tolist") else proba
        ranking = score_key_ranking(proba_rows, pt_bytes)
        write_rankings(outdir, byte_pos, ranking, args.top_k)

        if ranking:
            best_key = int(ranking[0]["key"])
            runner_key = int(ranking[1]["key"] if len(ranking) > 1 else best_key)
            write_feature_contrib(outdir, byte_pos, feature_headers, X, proba_rows, proba_rows, best_key, runner_key)

        tk = int(true_key[byte_pos]) if true_key is not None and byte_pos < len(true_key) else None
        rows.append(
            {
                "byte_pos": int(byte_pos),
                "best_key": int(ranking[0]["key"]) if ranking else -1,
                "true_key": int(tk) if tk is not None else None,
                "top_k": ranking[: max(1, int(args.top_k))],
            }
        )

    (outdir / "partial_online_summary.json").write_text(
        json.dumps(
            {
                "model_dir": str(model_dir),
                "observations_csv": str(Path(args.observations_csv).resolve()),
                "byte_positions": byte_positions,
                "results": rows,
            },
            indent=2,
            ensure_ascii=False,
        )
        + "\n"
    )
    print(f"[recover-tree] done: outdir={outdir}")


if __name__ == "__main__":
    main()
