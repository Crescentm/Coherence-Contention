#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import statistics
import subprocess
import sys
from pathlib import Path

from ch5_common import collect_host_facts, timestamped_outdir_ch5, write_json, write_lines
from experiment_common import print_banner, require_root


SCRIPT_DIR = Path(__file__).resolve().parent
RUN_AES_TOGGLE = SCRIPT_DIR / "run_aes_toggle.py"


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Chapter 6 demo: principle validation of cache-side defense effects."
    )
    ap.add_argument("--outdir", default="")
    ap.add_argument("--iters", type=int, default=1500)
    ap.add_argument("--qemu-cpu", type=int, default=32)
    ap.add_argument("--cpu-model", default="host,pmu=on")
    ap.add_argument("--guest-extra-cmdline", default="nokaslr norandmaps")
    ap.add_argument("--smp", default="1")
    ap.add_argument("--mem", default="4G")
    ap.add_argument("--vm-ready-timeout-s", type=int, default=300)
    ap.add_argument("--te0-file-offset", type=lambda x: int(x, 0), default=0xF60)
    ap.add_argument("--contention-burst", type=int, default=16)
    ap.add_argument(
        "--throttle-delay-us",
        type=int,
        default=50,
        help="Inter-probe delay used to emulate host bandwidth throttling for contention probing.",
    )
    return ap.parse_args()


def run_case(
    args: argparse.Namespace,
    outdir: Path,
    label: str,
    probe_mode: str,
    probe_burst: int,
    probe_delay_us: int,
    *,
    resctrl_enable: bool = False,
    host_mba: int = 0,
    set_host_uc: bool = False,
) -> dict:
    case_dir = outdir / label
    cmd = [
        sys.executable,
        str(RUN_AES_TOGGLE),
        "--outdir",
        str(case_dir),
        "--iters",
        str(int(args.iters)),
        "--te0-file-offset",
        hex(int(args.te0_file_offset)),
        "--qemu-cpu",
        str(int(args.qemu_cpu)),
        "--cpu-model",
        str(args.cpu_model),
        "--guest-extra-cmdline",
        str(args.guest_extra_cmdline),
        "--smp",
        str(args.smp),
        "--mem",
        str(args.mem),
        "--vm-ready-timeout-s",
        str(int(args.vm_ready_timeout_s)),
        "--probe-mode",
        str(probe_mode),
        "--probe-burst",
        str(int(probe_burst)),
        "--probe-delay-us",
        str(int(probe_delay_us)),
        "--probe-score-mode",
        "mean",
    ]
    if resctrl_enable:
        cmd.extend(["--resctrl-enable", "--resctrl-prefix", f"ch6_{label}"])
    if int(host_mba) > 0:
        cmd.extend(["--resctrl-host-mba", str(int(host_mba))])
    if set_host_uc:
        cmd.append("--set-host-uc")
    if label != "baseline_coherence":
        cmd.append("--skip-build")
    print(f"[ch6-demo] case={label}: {' '.join(cmd)}")
    cp = subprocess.run(cmd, check=False)
    rec = {
        "label": label,
        "probe_mode": probe_mode,
        "probe_burst": int(probe_burst),
        "probe_delay_us": int(probe_delay_us),
        "resctrl_enable": int(bool(resctrl_enable)),
        "host_mba": int(host_mba),
        "set_host_uc": int(bool(set_host_uc)),
        "returncode": int(cp.returncode),
        "outdir": str(case_dir),
    }
    metrics_path = case_dir / "aes_toggle_analysis.json"
    if cp.returncode == 0 and metrics_path.exists():
        rec.update(json.loads(metrics_path.read_text()))
    return rec


def derive_summary(rows: list[dict]) -> dict:
    by = {str(r["label"]): r for r in rows}
    out: dict[str, object] = {"cases": rows}
    base_coh = by.get("baseline_coherence")
    pqos_coh = by.get("pqos_isolated_coherence")
    uc_coh = by.get("defended_uc_like")
    base_cnt = by.get("baseline_contention")
    pqos_cnt = by.get("pqos_isolated_contention")
    mba_cnt = by.get("defended_mba_contention")

    def compare(a: dict | None, b: dict | None) -> dict | None:
        if not a or not b or a.get("returncode") != 0 or b.get("returncode") != 0:
            return None
        sep0 = abs(float(a.get("separation_median", 0.0)))
        sep1 = abs(float(b.get("separation_median", 0.0)))
        snr0 = abs(float(a.get("snr", 0.0)))
        snr1 = abs(float(b.get("snr", 0.0)))
        return {
            "baseline_sep": sep0,
            "defended_sep": sep1,
            "sep_ratio_defended_over_baseline": (sep1 / sep0) if sep0 > 0 else None,
            "baseline_snr": snr0,
            "defended_snr": snr1,
            "snr_ratio_defended_over_baseline": (snr1 / snr0) if snr0 > 0 else None,
        }

    coh_pqos = compare(base_coh, pqos_coh)
    coh_uc = compare(base_coh, uc_coh)
    cnt_pqos = compare(base_cnt, pqos_cnt)
    cnt_mba = compare(base_cnt, mba_cnt)
    if coh_pqos:
        out["coherence_pqos_effect"] = coh_pqos
    if coh_uc:
        out["coherence_uc_like_effect"] = coh_uc
    if cnt_pqos:
        out["contention_pqos_effect"] = cnt_pqos
    if cnt_mba:
        out["contention_mba_effect"] = cnt_mba
    return out


def main() -> None:
    args = parse_args()
    require_root("[!] run_ch6_defense_demo.py requires root.")

    outdir = Path(args.outdir).resolve() if args.outdir else timestamped_outdir_ch5("ch6_defense_demo")
    outdir.mkdir(parents=True, exist_ok=True)
    print_banner("Chapter 6 Defense Demo", outdir)
    collect_host_facts(outdir)

    cases = [
        ("baseline_coherence", "cacheable", 1, 0, False, 0, False),
        ("pqos_isolated_coherence", "cacheable", 1, 0, True, 0, False),
        ("defended_host_uc", "cacheable", 1, 0, False, 0, True),
        ("baseline_contention", "nocache", int(args.contention_burst), 0, False, 0, False),
        ("pqos_isolated_contention", "nocache", int(args.contention_burst), 0, True, 0, False),
        ("defended_mba_contention", "nocache", int(args.contention_burst), 0, True, int(args.throttle_delay_us), False),
    ]

    rows: list[dict] = []
    for label, probe_mode, probe_burst, probe_delay_us, resctrl_enable, host_mba, set_host_uc in cases:
        rows.append(
            run_case(
                args,
                outdir,
                label,
                probe_mode,
                probe_burst,
                probe_delay_us,
                resctrl_enable=resctrl_enable,
                host_mba=host_mba,
                set_host_uc=set_host_uc,
            )
        )

    summary = derive_summary(rows)
    write_json(outdir / "defense_demo_summary.json", summary)

    with (outdir / "defense_demo_summary.csv").open("w", newline="") as fp:
        wr = csv.writer(fp)
        wr.writerow(
            [
                "label",
                "probe_mode",
                "probe_burst",
                "probe_delay_us",
                "returncode",
                "n_a",
                "n_b",
                "median_a",
                "median_b",
                "mean_a",
                "mean_b",
                "separation_median",
                "snr",
            ]
        )
        for row in rows:
            wr.writerow(
                [
                    row.get("label", ""),
                    row.get("probe_mode", ""),
                    row.get("probe_burst", ""),
                    row.get("probe_delay_us", ""),
                    row.get("returncode", ""),
                    row.get("n_a", ""),
                    row.get("n_b", ""),
                    row.get("median_a", ""),
                    row.get("median_b", ""),
                    row.get("mean_a", ""),
                    row.get("mean_b", ""),
                    row.get("separation_median", ""),
                    row.get("snr", ""),
                ]
            )

    lines = ["Chapter 6 defense demo summary", ""]
    for row in rows:
        lines.extend(
            [
                f"[{row.get('label','')}]",
                f"probe_mode={row.get('probe_mode','')} burst={row.get('probe_burst','')} delay_us={row.get('probe_delay_us','')}",
                f"returncode={row.get('returncode','')}",
                f"median_a={row.get('median_a','')} median_b={row.get('median_b','')}",
                f"mean_a={row.get('mean_a','')} mean_b={row.get('mean_b','')}",
                f"separation_median={row.get('separation_median','')} snr={row.get('snr','')}",
                "",
            ]
        )
    coh_pqos = summary.get("coherence_pqos_effect", {})
    coh_uc = summary.get("coherence_uc_like_effect", {})
    cnt_pqos = summary.get("contention_pqos_effect", {})
    cnt_mba = summary.get("contention_mba_effect", {})
    if coh_pqos:
        lines.extend(
            [
                "[coherence_pqos_effect]",
                f"baseline_sep={coh_pqos.get('baseline_sep','')}",
                f"defended_sep={coh_pqos.get('defended_sep','')}",
                f"sep_ratio_defended_over_baseline={coh_pqos.get('sep_ratio_defended_over_baseline','')}",
                f"baseline_snr={coh_pqos.get('baseline_snr','')}",
                f"defended_snr={coh_pqos.get('defended_snr','')}",
                f"snr_ratio_defended_over_baseline={coh_pqos.get('snr_ratio_defended_over_baseline','')}",
                "",
            ]
        )
    if coh_uc:
        lines.extend(
            [
                "[coherence_uc_like_effect]",
                f"baseline_sep={coh_uc.get('baseline_sep','')}",
                f"defended_sep={coh_uc.get('defended_sep','')}",
                f"sep_ratio_defended_over_baseline={coh_uc.get('sep_ratio_defended_over_baseline','')}",
                f"baseline_snr={coh_uc.get('baseline_snr','')}",
                f"defended_snr={coh_uc.get('defended_snr','')}",
                f"snr_ratio_defended_over_baseline={coh_uc.get('snr_ratio_defended_over_baseline','')}",
                "",
            ]
        )
    if cnt_pqos:
        lines.extend(
            [
                "[contention_pqos_effect]",
                f"baseline_sep={cnt_pqos.get('baseline_sep','')}",
                f"defended_sep={cnt_pqos.get('defended_sep','')}",
                f"sep_ratio_defended_over_baseline={cnt_pqos.get('sep_ratio_defended_over_baseline','')}",
                f"baseline_snr={cnt_pqos.get('baseline_snr','')}",
                f"defended_snr={cnt_pqos.get('defended_snr','')}",
                f"snr_ratio_defended_over_baseline={cnt_pqos.get('snr_ratio_defended_over_baseline','')}",
                "",
            ]
        )
    if cnt_mba:
        lines.extend(
            [
                "[contention_mba_effect]",
                f"baseline_sep={cnt_mba.get('baseline_sep','')}",
                f"defended_sep={cnt_mba.get('defended_sep','')}",
                f"sep_ratio_defended_over_baseline={cnt_mba.get('sep_ratio_defended_over_baseline','')}",
                f"baseline_snr={cnt_mba.get('baseline_snr','')}",
                f"defended_snr={cnt_mba.get('defended_snr','')}",
                f"snr_ratio_defended_over_baseline={cnt_mba.get('snr_ratio_defended_over_baseline','')}",
            ]
        )
    write_lines(outdir / "defense_demo_summary.txt", lines)
    print(f"[ch6-demo] done: outdir={outdir}")


if __name__ == "__main__":
    main()
