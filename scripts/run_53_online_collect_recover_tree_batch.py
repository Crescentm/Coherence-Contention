#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
from pathlib import Path

from ch5_common import collect_host_facts, timestamped_outdir_ch5, write_json
from experiment_common import print_banner, require_root


SCRIPT_DIR = Path(__file__).resolve().parent
RUN_COLLECT = SCRIPT_DIR / "run_53_online_signal_collect.py"
RUN_RECOVER = SCRIPT_DIR / "run_53_online_tree_recovery.py"


def parse_args() -> tuple[argparse.Namespace, list[str], list[str]]:
    ap = argparse.ArgumentParser(
        description="Batch online signal collection followed by immediate tree-model recovery."
        ,
        allow_abbrev=False,
    )
    ap.add_argument("--runs", type=int, default=8)
    ap.add_argument("--batch-outdir", default="")
    ap.add_argument("--child-name", default="run")
    ap.add_argument("--model-dir", required=True)
    ap.add_argument("--byte-positions", default="0")
    ap.add_argument("--top-k", type=int, default=16)
    ap.add_argument("--true-key-hex", default="")
    ap.add_argument("--stop-on-fail", action="store_true")
    ap.add_argument("--recover-python", default="", help="Optional Python interpreter for tree recovery.")
    args, rest = ap.parse_known_args()
    if "--recover-args" in rest:
        idx = rest.index("--recover-args")
        collect_argv = rest[:idx]
        recover_argv = rest[idx + 1 :]
    else:
        collect_argv = rest
        recover_argv = []
    if collect_argv and collect_argv[0] == "--":
        collect_argv = collect_argv[1:]
    if recover_argv and recover_argv[0] == "--":
        recover_argv = recover_argv[1:]
    return args, collect_argv, recover_argv


def parse_summary(summary_json: Path, byte_positions: list[int]) -> dict[int, dict]:
    out: dict[int, dict] = {}
    if not summary_json.exists():
        return out
    obj = json.loads(summary_json.read_text())
    for row in obj.get("results", []):
        byte_pos = int(row.get("byte_pos", -1))
        if byte_pos not in byte_positions:
            continue
        top_k = row.get("top_k", []) or []
        true_key = row.get("true_key")
        true_rank = None
        if true_key is not None:
            for idx, ent in enumerate(top_k, start=1):
                if int(ent.get("key", -1)) == int(true_key):
                    true_rank = idx
                    break
        out[byte_pos] = {
            "best_key": row.get("best_key"),
            "true_key": true_key,
            "true_rank_in_topk": true_rank,
        }
    return out


def main() -> None:
    args, collect_argv, recover_argv = parse_args()
    require_root("[!] run_53_online_collect_recover_tree_batch.py requires root because collection requires root.")

    byte_positions = [int(x.strip(), 0) for x in str(args.byte_positions).split(",") if x.strip()]
    if not byte_positions:
        raise SystemExit("no valid byte positions")

    outdir = (
        Path(args.batch_outdir).resolve()
        if args.batch_outdir
        else timestamped_outdir_ch5("exp5_3_online_collect_recover_tree_batch")
    )
    outdir.mkdir(parents=True, exist_ok=True)
    print_banner(f"Experiment 5.3 Online Collect+Recover Tree Batch ({args.runs} runs)", outdir)
    collect_host_facts(outdir)

    recover_python = str(Path(args.recover_python).resolve()) if args.recover_python else sys.executable

    manifest: dict = {
        "runs": int(args.runs),
        "batch_outdir": str(outdir),
        "model_dir": str(Path(args.model_dir).resolve()),
        "byte_positions": byte_positions,
        "children": [],
    }
    summary_rows: list[list[str | int]] = []

    for i in range(1, int(args.runs) + 1):
        child_root = outdir / f"{args.child_name}_{i:02d}"
        collect_out = child_root / "collect"
        recover_out = child_root / "recover"

        collect_cmd = [sys.executable, str(RUN_COLLECT), *collect_argv, "--outdir", str(collect_out)]
        if i > 1:
            collect_cmd.append("--skip-build")

        recover_cmd = [
            recover_python,
            str(RUN_RECOVER),
            "--model-dir",
            str(Path(args.model_dir).resolve()),
            "--observations-csv",
            str(collect_out / "signal_observations.csv"),
            "--byte-positions",
            str(args.byte_positions),
            "--top-k",
            str(int(args.top_k)),
            "--outdir",
            str(recover_out),
            *recover_argv,
        ]
        if str(args.true_key_hex).strip():
            recover_cmd.extend(["--true-key-hex", str(args.true_key_hex).strip()])

        print(f"[batch-tree] collect {i}/{args.runs}: {' '.join(collect_cmd)}")
        cp_collect = subprocess.run(collect_cmd, check=False)

        cp_recover_rc = -1
        parsed = {}
        if cp_collect.returncode == 0:
            print(f"[batch-tree] recover {i}/{args.runs}: {' '.join(recover_cmd)}")
            cp_recover = subprocess.run(recover_cmd, check=False)
            cp_recover_rc = int(cp_recover.returncode)
            if cp_recover_rc == 0:
                parsed = parse_summary(recover_out / "partial_online_summary.json", byte_positions)

        child_record = {
            "index": int(i),
            "root": str(child_root),
            "collect_outdir": str(collect_out),
            "recover_outdir": str(recover_out),
            "collect_returncode": int(cp_collect.returncode),
            "recover_returncode": int(cp_recover_rc),
            "collect_cmd": collect_cmd,
            "recover_cmd": recover_cmd,
            "parsed_summary": parsed,
        }
        manifest["children"].append(child_record)
        write_json(outdir / "batch_manifest.json", manifest)

        for byte_pos in byte_positions:
            item = parsed.get(byte_pos, {})
            summary_rows.append(
                [
                    int(i),
                    int(byte_pos),
                    f"0x{int(item['best_key']):02x}" if item.get("best_key") is not None else "",
                    f"0x{int(item['true_key']):02x}" if item.get("true_key") is not None else "",
                    int(item["true_rank_in_topk"]) if item.get("true_rank_in_topk") is not None else "",
                    int(cp_collect.returncode),
                    int(cp_recover_rc),
                ]
            )

        if args.stop_on_fail and (cp_collect.returncode != 0 or cp_recover_rc != 0):
            raise SystemExit(
                f"[batch-tree] failed: run={i} collect_rc={cp_collect.returncode} recover_rc={cp_recover_rc}"
            )

    with (outdir / "batch_recovery_summary.csv").open("w", newline="") as fp:
        wr = csv.writer(fp)
        wr.writerow(
            [
                "run",
                "byte_pos",
                "best_key",
                "true_key",
                "true_rank_in_topk",
                "collect_returncode",
                "recover_returncode",
            ]
        )
        wr.writerows(summary_rows)

    write_json(outdir / "batch_recovery_summary.json", {"rows": summary_rows})
    print(f"[batch-tree] done: outdir={outdir}")


if __name__ == "__main__":
    main()
