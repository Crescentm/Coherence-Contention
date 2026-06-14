#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Online partial-byte recovery using an offline-trained RRMB Gaussian-mixture model."
    )
    ap.add_argument("--model-json", required=True)
    ap.add_argument("--observations-csv", required=True, help="signal_observations.csv from run_53_signal_collect.py")
    ap.add_argument("--byte-positions", default="0,4,8,12")
    ap.add_argument("--top-k", type=int, default=8)
    ap.add_argument("--true-key-hex", default="", help="Optional full true key hex for contribution comparison.")
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


def rrmb_count(vals: list[float], d_lo: float, d_hi: float) -> int:
    return sum(1 for x in vals if float(d_lo) <= float(x) < float(d_hi))


def logsumexp2(a: float, b: float) -> float:
    m = max(a, b)
    return m + math.log(math.exp(a - m) + math.exp(b - m))


def gaussian_diag_logpdf(x: list[float], mu: list[float], var: list[float]) -> float:
    total = 0.0
    for xv, mv, vv in zip(x, mu, var):
        v = max(1e-9, float(vv))
        d = float(xv) - float(mv)
        total += -0.5 * (math.log(2.0 * math.pi * v) + (d * d) / v)
    return total


def gaussian_diag_logpdf_terms(x: list[float], mu: list[float], var: list[float]) -> list[float]:
    terms: list[float] = []
    for xv, mv, vv in zip(x, mu, var):
        v = max(1e-9, float(vv))
        d = float(xv) - float(mv)
        terms.append(-0.5 * (math.log(2.0 * math.pi * v) + (d * d) / v))
    return terms


@dataclass
class GaussianComponent:
    weight: float
    mean: list[float]
    var: list[float]


@dataclass
class EntryModel:
    entry: int
    components: list[GaussianComponent]

    def logpdf(self, x: list[float]) -> float:
        if not self.components:
            return -1e18
        if len(self.components) == 1:
            c = self.components[0]
            return math.log(max(1e-9, c.weight)) + gaussian_diag_logpdf(x, c.mean, c.var)
        c0, c1 = self.components[0], self.components[1]
        a = math.log(max(1e-9, c0.weight)) + gaussian_diag_logpdf(x, c0.mean, c0.var)
        b = math.log(max(1e-9, c1.weight)) + gaussian_diag_logpdf(x, c1.mean, c1.var)
        return logsumexp2(a, b)

    def feature_contrib(self, x: list[float]) -> tuple[list[float], float]:
        if not self.components:
            return [0.0 for _ in x], -1e18
        if len(self.components) == 1:
            c = self.components[0]
            terms = gaussian_diag_logpdf_terms(x, c.mean, c.var)
            return terms, math.log(max(1e-9, c.weight))
        c0, c1 = self.components[0], self.components[1]
        t0 = gaussian_diag_logpdf_terms(x, c0.mean, c0.var)
        t1 = gaussian_diag_logpdf_terms(x, c1.mean, c1.var)
        l0 = math.log(max(1e-9, c0.weight)) + sum(t0)
        l1 = math.log(max(1e-9, c1.weight)) + sum(t1)
        m = max(l0, l1)
        p0 = math.exp(l0 - m)
        p1 = math.exp(l1 - m)
        z = max(1e-9, p0 + p1)
        g0 = p0 / z
        g1 = p1 / z
        mix_terms = [g0 * a + g1 * b for a, b in zip(t0, t1)]
        mix_offset = g0 * math.log(max(1e-9, c0.weight)) + g1 * math.log(max(1e-9, c1.weight))
        return mix_terms, mix_offset


@dataclass
class ByteModel:
    byte_pos: int
    feature_headers: list[str]
    role_specs: dict[str, int]
    drange_meta: dict[str, dict[str, float]]
    entry_models: dict[int, EntryModel]


def load_model(path: Path) -> dict[int, ByteModel]:
    raw = json.loads(path.read_text())
    out: dict[int, ByteModel] = {}
    for byte_obj in raw["bytes"]:
        byte_pos = int(byte_obj["byte_pos"])
        role_specs = {str(x["name"]): int(x["line"]) for x in byte_obj["role_specs"]}
        drange_meta = {str(k): {"d_lo": float(v["d_lo"]), "d_hi": float(v["d_hi"])} for k, v in byte_obj["drange_meta"].items()}
        entry_models: dict[int, EntryModel] = {}
        for entry_str, model_obj in byte_obj["entries"].items():
            comps = [
                GaussianComponent(
                    weight=float(comp["weight"]),
                    mean=[float(x) for x in comp["mean"]],
                    var=[float(x) for x in comp["var"]],
                )
                for comp in model_obj["components"]
            ]
            entry_models[int(entry_str)] = EntryModel(entry=int(entry_str), components=comps)
        out[byte_pos] = ByteModel(
            byte_pos=byte_pos,
            feature_headers=[str(x) for x in byte_obj["feature_headers"]],
            role_specs=role_specs,
            drange_meta=drange_meta,
            entry_models=entry_models,
        )
    return out


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


def feature_vector(obs: dict[str, Any], model: ByteModel) -> list[float]:
    role_counts: dict[str, float] = {}
    for role, line in model.role_specs.items():
        key = f"cont_{role}"
        if key not in model.drange_meta:
            continue
        meta = model.drange_meta[key]
        bursts = obs["bursts_by_line"].get(int(line), [])
        role_counts[key] = float(rrmb_count(bursts, meta["d_lo"], meta["d_hi"]))
    vec: list[float] = []
    for feat in model.feature_headers:
        if feat in role_counts:
            vec.append(float(role_counts[feat]))
        elif feat == "cont_after_max":
            vec.append(max(role_counts.get("cont_after_0", 0.0), role_counts.get("cont_after_1", 0.0)))
        elif feat == "cont_after_sum":
            vec.append(float(role_counts.get("cont_after_0", 0.0) + role_counts.get("cont_after_1", 0.0)))
        else:
            vec.append(0.0)
    return vec


def score_one_byte(model: ByteModel, observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ranking: list[dict[str, Any]] = []
    for key_guess in range(256):
        total = 0.0
        valid = 0
        for obs in observations:
            entry = int(obs["pt"][model.byte_pos]) ^ int(key_guess)
            em = model.entry_models.get(entry)
            if em is None:
                continue
            total += em.logpdf(feature_vector(obs, model))
            valid += 1
        ranking.append(
            {
                "key": int(key_guess),
                "score": float(total),
                "avg_score": float(total / max(1, valid)),
                "valid_samples": int(valid),
            }
        )
    ranking.sort(key=lambda r: (float(r["score"]), float(r["avg_score"])), reverse=True)
    return ranking


def feature_contributions_for_key(model: ByteModel, observations: list[dict[str, Any]], key_guess: int) -> dict[str, float]:
    contrib = {h: 0.0 for h in model.feature_headers}
    contrib["mixture_offset"] = 0.0
    for obs in observations:
        entry = int(obs["pt"][model.byte_pos]) ^ int(key_guess)
        em = model.entry_models.get(entry)
        if em is None:
            continue
        x = feature_vector(obs, model)
        terms, offset = em.feature_contrib(x)
        for h, v in zip(model.feature_headers, terms):
            contrib[h] += float(v)
        contrib["mixture_offset"] += float(offset)
    return contrib


def write_feature_contrib(
    outdir: Path,
    byte_pos: int,
    model: ByteModel,
    observations: list[dict[str, Any]],
    ranking: list[dict[str, Any]],
) -> None:
    if not ranking:
        return
    best_key = int(ranking[0]["key"])
    ref_key = int(ranking[1]["key"] if len(ranking) > 1 else best_key)
    best = feature_contributions_for_key(model, observations, best_key)
    ref = feature_contributions_for_key(model, observations, ref_key)
    path = outdir / f"byte_{byte_pos:02d}_feature_contrib.csv"
    with path.open("w", newline="") as fp:
        wr = csv.writer(fp)
        wr.writerow(["feature", "best_key", "best_contrib", "ref_key", "ref_contrib", "gap_best_minus_ref"])
        for feat in [*model.feature_headers, "mixture_offset"]:
            wr.writerow([
                feat,
                f"0x{best_key:02x}",
                f"{float(best.get(feat, 0.0)):.6f}",
                f"0x{ref_key:02x}",
                f"{float(ref.get(feat, 0.0)):.6f}",
                f"{float(best.get(feat, 0.0) - ref.get(feat, 0.0)):.6f}",
            ])
    try:
        import matplotlib.pyplot as plt  # type: ignore

        feats = [*model.feature_headers, "mixture_offset"]
        gaps = [float(best.get(f, 0.0) - ref.get(f, 0.0)) for f in feats]
        order = sorted(range(len(feats)), key=lambda i: abs(gaps[i]), reverse=True)
        feats = [feats[i] for i in order]
        gaps = [gaps[i] for i in order]
        plt.figure(figsize=(9, max(4, 0.35 * len(feats))))
        colors = ["#2F5D8A" if g >= 0 else "#B33A39" for g in gaps]
        plt.barh(range(len(feats)), gaps, color=colors)
        plt.yticks(range(len(feats)), feats)
        plt.gca().invert_yaxis()
        plt.axvline(0.0, color="black", linewidth=0.8)
        plt.xlabel("Best key contribution gap")
        plt.title(f"Byte {byte_pos}: feature contribution gap (0x{best_key:02x} vs 0x{ref_key:02x})")
        plt.tight_layout()
        plt.savefig(outdir / f"byte_{byte_pos:02d}_feature_contrib.png", dpi=160)
        plt.close()
    except Exception:
        pass


def write_rankings(outdir: Path, byte_pos: int, ranking: list[dict[str, Any]], top_k: int) -> None:
    outdir.mkdir(parents=True, exist_ok=True)
    with (outdir / f"byte_{byte_pos:02d}_ranking.csv").open("w", newline="") as fp:
        wr = csv.writer(fp)
        wr.writerow(["rank", "key", "score", "avg_score", "valid_samples"])
        for idx, row in enumerate(ranking[: max(1, int(top_k))], start=1):
            wr.writerow([idx, f"0x{int(row['key']):02x}", f"{float(row['score']):.6f}", f"{float(row['avg_score']):.6f}", int(row["valid_samples"])])


def main() -> None:
    args = parse_args()
    model = load_model(Path(args.model_json).resolve())
    observations = load_observations(Path(args.observations_csv).resolve())
    byte_positions = parse_byte_positions(args.byte_positions)
    outdir = Path(args.outdir).resolve() if args.outdir else Path.cwd() / "partial_online_recovery"
    outdir.mkdir(parents=True, exist_ok=True)
    true_key = bytes.fromhex(str(args.true_key_hex).strip()) if str(args.true_key_hex).strip() else None

    rows: list[dict[str, Any]] = []
    for byte_pos in byte_positions:
        if byte_pos not in model:
            continue
        ranking = score_one_byte(model[byte_pos], observations)
        write_rankings(outdir, byte_pos, ranking, args.top_k)
        tk = int(true_key[byte_pos]) if true_key is not None and byte_pos < len(true_key) else None
        write_feature_contrib(outdir, byte_pos, model[byte_pos], observations, ranking)
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
                "model_json": str(Path(args.model_json).resolve()),
                "observations_csv": str(Path(args.observations_csv).resolve()),
                "byte_positions": byte_positions,
                "results": rows,
            },
            indent=2,
            ensure_ascii=False,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
