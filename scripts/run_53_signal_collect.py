#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

import run_53 as core
import run_53_role_signal as rs
from ch5_common import collect_host_facts, timestamped_outdir_ch5, write_json
from experiment_common import ensure_artifacts, print_banner, require_root, stop_proc


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Collect raw Ch5 signal data for offline template training.")
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
    ap.add_argument("--byte-pos", type=int, default=0)
    ap.add_argument("--line-reps", type=int, default=8)
    ap.add_argument("--confirm-pages", type=int, default=4)
    ap.add_argument("--confirm-line-reps", type=int, default=2)
    ap.add_argument("--aes-sync-phase1-repeats", type=int, default=12)
    ap.add_argument("--noise-lines", default="")
    ap.add_argument("--feature-topk", type=int, default=12)
    ap.add_argument("--boundary-line-window", type=int, default=2)
    ap.add_argument("--lines-per-side", type=int, default=2)
    ap.add_argument("--entries", default="all")
    ap.add_argument("--samples-per-entry", type=int, default=16)
    ap.add_argument("--contention-burst", type=int, default=16)
    ap.add_argument("--fixed-rest-bytes", dest="fixed_rest_bytes", action="store_true")
    ap.add_argument("--random-rest-bytes", dest="fixed_rest_bytes", action="store_false")
    ap.set_defaults(fixed_rest_bytes=True)
    ap.add_argument("--random-seed", type=int, default=0)
    return ap.parse_args()


def main() -> None:
    args = parse_args()
    require_root("[!] run_53_signal_collect.py requires root.")

    args.enable_aes_sync = True
    args.enable_contention = False
    args.fusion_mode = "phase1_only"
    args.theta_mode = "line_mid"
    args.theta = 0
    args.theta_scale = 0.5
    args.score_mode = "correlation"
    args.recover_mode = "two_stage_nibble"

    outdir = Path(args.outdir).resolve() if args.outdir else timestamped_outdir_ch5("exp5_3_signal_collect")
    outdir.mkdir(parents=True, exist_ok=True)
    print_banner("Experiment 5.3: Signal Collection", outdir)

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

        line_rows = core.scan_page_lines(vm_ctl, te0_gpa, args, outdir)
        noise_lines = core.parse_noise_lines(args.noise_lines)
        boundary = rs.find_page_boundary(rs.compute_entry_layout(te0_gpa, int(args.byte_pos)))
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
        entry_boundary = int(boundary["entry_before"])
        target_entries = rs.parse_entry_spec(args.entries, profile_entries=None, target_entries=None)

        observations = rs.collect_observations(
            vm_ctl,
            te0_gpa,
            args,
            byte_pos=int(args.byte_pos),
            boundary=boundary,
            entry_boundary=entry_boundary,
            selected_lines=selected_lines,
            feature_lines=feature_lines,
            target_entries=target_entries,
            samples_per_entry=int(args.samples_per_entry),
            out_csv=outdir / "signal_observations.csv",
            collect_cont_features=True,
            cont_repeats=int(args.contention_burst),
        )

        write_json(
            outdir / "signal_meta.json",
            {
                "byte_pos": int(args.byte_pos),
                "te0_gpa": f"0x{te0_gpa:x}",
                "te0_page_gpa": f"0x{te0_gpa & ~(core.PAGE_SZ - 1):x}",
                "static_page_boundary": boundary,
                "entry_boundary": int(entry_boundary),
                "entries": [int(x) for x in target_entries],
                "samples_per_entry": int(args.samples_per_entry),
                "contention_burst": int(args.contention_burst),
                "fixed_rest_bytes": int(bool(args.fixed_rest_bytes)),
                "selected_lines": selected_lines,
                "feature_lines": [int(x) for x in feature_lines],
                "role_specs": role_specs,
                "ranked_lines": ranked_lines,
                "observation_count": int(len(observations)),
                "true_key_hex": core.TRUE_AES_KEY.hex(),
            },
        )
        print(f"[collect] done: outdir={outdir}")
    finally:
        if vm_ctl is not None:
            vm_ctl.close()
        stop_proc(proc, timeout_s=10.0)


if __name__ == "__main__":
    main()
