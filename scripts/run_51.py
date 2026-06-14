#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

from ch5_common import (
    collect_host_facts,
    seed_51a_layout,
    timestamped_outdir_ch5,
    write_json,
    write_lines,
)
from experiment_common import (
    AMDSEV_DIR,
    GUEST_KERNEL,
    INITRAMFS,
    OVMF_FD,
    QEMU_BIN,
    SRC_DIR,
    ensure_artifacts,
    ensure_runtime_paths,
    now,
    print_banner,
    require_root,
    run_qemu_background,
    stop_proc,
)


def parse_crypto51_metrics(debugcon: Path) -> dict[str, str]:
    metrics: dict[str, str] = {}
    if not debugcon.exists():
        return metrics
    for raw in debugcon.read_text(errors="ignore").splitlines():
        line = raw.strip()
        if not line.startswith("CRYPTO51 "):
            continue
        payload = line[len("CRYPTO51 ") :]
        if "=" not in payload:
            continue
        key, value = payload.split("=", 1)
        metrics[key.strip()] = value.strip()
    return metrics


def wait_done(debugcon: Path, timeout_s: int) -> tuple[bool, bool]:
    start = time.time()
    last_size = -1
    while time.time() - start < timeout_s:
        if debugcon.exists():
            size = debugcon.stat().st_size
            if size != last_size:
                last_size = size
                txt = debugcon.read_text(errors="ignore")
                if "CRYPTO51_DONE" in txt:
                    return True, False
                if "CRYPTO51 error=" in txt:
                    return False, True
        time.sleep(1.0)
    return False, False


def _safe_nm_symbols(path: Path) -> list[str]:
    if not path.exists():
        return []
    try:
        out = subprocess.run(
            ["nm", "-A", str(path)],
            capture_output=True,
            text=True,
            check=False,
        )
    except Exception:
        return []
    if out.returncode != 0:
        return []
    return out.stdout.splitlines()


def collect_path_proofs() -> dict[str, str]:
    build_dir = SRC_DIR / "build"
    aes_noasm = build_dir / "guest_aes_bench_noasm"
    aes_asm = build_dir / "guest_aes_bench_asm"
    rsa_bench = build_dir / "guest_rsa_bench"
    noasm_lib = build_dir / "openssl_noasm" / "libcrypto.a"
    asm_lib = build_dir / "openssl_asm" / "libcrypto.a"

    noasm_lines = _safe_nm_symbols(aes_noasm)
    asm_lines = _safe_nm_symbols(aes_asm)
    rsa_lines = _safe_nm_symbols(rsa_bench)
    noasm_lib_lines = _safe_nm_symbols(noasm_lib)
    asm_lib_lines = _safe_nm_symbols(asm_lib)

    def contains(lines: list[str], needle: str) -> bool:
        return any(needle in ln for ln in lines)

    proofs: dict[str, str] = {}
    proofs["proof_guest_aes_noasm_exists"] = "1" if aes_noasm.exists() else "0"
    proofs["proof_guest_aes_asm_exists"] = "1" if aes_asm.exists() else "0"
    proofs["proof_guest_rsa_bench_exists"] = "1" if rsa_bench.exists() else "0"
    proofs["proof_openssl_noasm_lib_exists"] = "1" if noasm_lib.exists() else "0"
    proofs["proof_openssl_asm_lib_exists"] = "1" if asm_lib.exists() else "0"

    proofs["proof_aes_noasm_has_aesni_symbol"] = (
        "1" if contains(noasm_lines, "aesni_") else "0"
    )
    proofs["proof_aes_noasm_has_vpaes_symbol"] = (
        "1" if contains(noasm_lines, "vpaes_") else "0"
    )
    proofs["proof_aes_noasm_has_aes_encrypt"] = (
        "1" if contains(noasm_lines, " AES_encrypt") else "0"
    )
    proofs["proof_noasm_lib_has_aesni_symbol"] = (
        "1" if contains(noasm_lib_lines, "aesni_") else "0"
    )
    proofs["proof_noasm_lib_has_vpaes_symbol"] = (
        "1" if contains(noasm_lib_lines, "vpaes_") else "0"
    )

    proofs["proof_aes_asm_has_aesni_symbol"] = (
        "1" if contains(asm_lines, "aesni_") else "0"
    )
    proofs["proof_aes_asm_has_vpaes_symbol"] = (
        "1" if contains(asm_lines, "vpaes_") else "0"
    )
    proofs["proof_aes_asm_has_aes_encrypt"] = (
        "1" if contains(asm_lines, " AES_encrypt") else "0"
    )
    proofs["proof_asm_lib_has_aesni_symbol"] = (
        "1" if contains(asm_lib_lines, "aesni_") else "0"
    )
    proofs["proof_asm_lib_has_vpaes_symbol"] = (
        "1" if contains(asm_lib_lines, "vpaes_") else "0"
    )

    proofs["proof_rsa_has_var_api_symbol"] = (
        "1" if contains(rsa_lines, " BN_mod_exp_mont") else "0"
    )
    proofs["proof_rsa_has_const_api_symbol"] = (
        "1" if contains(rsa_lines, " BN_mod_exp_mont_consttime") else "0"
    )
    return proofs


def _looks_like_lookup_load(insn: str) -> bool:
    low = insn.lower()
    has_scaled_mem = bool(
        re.search(r"\[[^\]]+\*[1248]\]", low) or re.search(r"\([^)]*,[^)]*,[1248]\)", low)
    )
    if not has_scaled_mem:
        return False
    return bool(re.search(r"\b(mov|movz|movs|vmov|vpmov)\w*\b", low))


def _parse_perf_annotate(text: str) -> dict[str, str]:
    rows: list[tuple[float, str]] = []
    for raw in text.splitlines():
        # format A: "  3.14%  mov ..."
        m = re.search(r"^\s*([0-9]+(?:\.[0-9]+)?)%\s*(?:\|)?\s*(.*)$", raw)
        if m:
            pct = float(m.group(1))
            insn = m.group(2).strip()
            if insn:
                rows.append((pct, insn))
            continue

        # format B (this platform): "  3.14 :   40281e:  movl ..."
        m = re.search(
            r"^\s*([0-9]+(?:\.[0-9]+)?)\s*:\s+[0-9a-fx]+\s*:\s+(.*)$",
            raw,
            flags=re.IGNORECASE,
        )
        if m:
            pct = float(m.group(1))
            insn = m.group(2).strip()
            if insn:
                rows.append((pct, insn))
            continue

    aesenc_pct = 0.0
    lookup_load_pct = 0.0
    for pct, insn in rows:
        low = insn.lower()
        if re.search(r"\b(?:vaesenc|aesenc|vaesenclast|aesenclast)\b", low):
            aesenc_pct += pct
        if _looks_like_lookup_load(insn):
            lookup_load_pct += pct

    top_rows = sorted(rows, key=lambda it: it[0], reverse=True)[:12]
    top_text = " | ".join(f"{pct:.2f}% {insn}" for pct, insn in top_rows)
    return {
        "parsed_rows": str(len(rows)),
        "hotspot_top12": top_text,
        "aesenc_pct_sum": f"{aesenc_pct:.4f}",
        "lookup_load_pct_sum": f"{lookup_load_pct:.4f}",
    }


def _resolve_perf_bin(explicit: str) -> tuple[str | None, str]:
    candidates: list[str] = []
    if explicit:
        candidates.append(explicit)
    env_perf = os.environ.get("PERF_BIN", "")
    if env_perf:
        candidates.append(env_perf)
    which_perf = shutil.which("perf")
    if which_perf:
        candidates.append(which_perf)

    candidates.extend(
        [
            f"/usr/lib/linux-tools-{os.uname().release}/perf",
            "/usr/bin/perf",
            "<AMDSEV_DIR>/linux/guest/tools/perf/perf",
            "<AMDSEV_DIR>/linux/host/tools/perf/perf",
        ]
    )

    checked: list[str] = []

    def perf_usable(path: str) -> tuple[bool, str]:
        try:
            cp = subprocess.run(
                [path, "--version"],
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
        except Exception as e:
            return False, f"probe_exc:{e}"
        txt = ((cp.stdout or "") + "\n" + (cp.stderr or "")).strip().lower()
        if cp.returncode != 0:
            return False, f"rc={cp.returncode}"
        if "perf version" in txt:
            return True, "ok"
        if "perf not found for kernel" in txt:
            return False, "wrapper_no_kernel_perf"
        return False, "no_perf_version_signature"

    seen: set[str] = set()
    for c in candidates:
        if not c or c in seen:
            continue
        seen.add(c)
        checked.append(c)
        if os.path.isfile(c) and os.access(c, os.X_OK):
            ok, reason = perf_usable(c)
            if ok:
                return c, "ok"
            checked.append(f"{c}({reason})")
    return None, "missing: " + ",".join(checked)


def run_aes_annotate_profile(outdir: Path, ops: int, perf_bin_explicit: str) -> dict[str, str]:
    out: dict[str, str] = {}
    perf_bin, perf_status = _resolve_perf_bin(perf_bin_explicit)
    if not perf_bin:
        out["aes_annotate_status"] = "skipped_perf_not_found"
        out["aes_annotate_perf_lookup"] = perf_status
        return out

    profile_dir = outdir / "aes_path_profile"
    profile_dir.mkdir(parents=True, exist_ok=True)

    cases = [
        ("noasm", SRC_DIR / "build" / "guest_aes_bench_noasm"),
        ("aesni", SRC_DIR / "build" / "guest_aes_bench_asm"),
    ]

    out["aes_annotate_status"] = "ok"
    out["aes_annotate_perf_bin"] = perf_bin
    out["aes_annotate_ops"] = str(ops)

    for tag, bin_path in cases:
        if not bin_path.exists():
            out[f"aes_annotate_{tag}_status"] = "missing_binary"
            out["aes_annotate_status"] = "partial_or_failed"
            continue

        perf_data = profile_dir / f"perf_{tag}.data"
        record_log = profile_dir / f"perf_record_{tag}.log"
        annotate_txt = profile_dir / f"annotate_{tag}.txt"

        rec = subprocess.run(
            [
                perf_bin,
                "record",
                "-q",
                "-e",
                "cycles:u",
                "-o",
                str(perf_data),
                "--",
                str(bin_path),
                str(ops),
            ],
            cwd=str(SRC_DIR),
            capture_output=True,
            text=True,
            check=False,
        )
        record_log.write_text((rec.stdout or "") + (rec.stderr or ""))
        if rec.returncode != 0:
            out[f"aes_annotate_{tag}_status"] = f"record_failed_rc_{rec.returncode}"
            out["aes_annotate_status"] = "partial_or_failed"
            continue

        symbols = ["AES_encrypt"]
        if tag == "aesni":
            symbols.extend(
                [
                    "_x86_64_AES_encrypt_compact",
                    "aesni_encrypt",
                    "vpaes_encrypt",
                ]
            )

        merged_sections: list[str] = []
        ok_symbols: list[str] = []
        last_rc = 0
        for sym in symbols:
            ann = subprocess.run(
                [
                    perf_bin,
                    "annotate",
                    "--stdio",
                    "--symbol",
                    sym,
                    "-i",
                    str(perf_data),
                ],
                cwd=str(SRC_DIR),
                capture_output=True,
                text=True,
                check=False,
            )
            last_rc = ann.returncode
            ann_text = (ann.stdout or "") + (ann.stderr or "")
            if ann.returncode != 0:
                continue
            if not ann_text.strip():
                continue
            ok_symbols.append(sym)
            merged_sections.append(f"===== SYMBOL {sym} =====\n{ann_text}")

        merged_text = "\n\n".join(merged_sections)
        annotate_txt.write_text(merged_text)
        if not ok_symbols:
            out[f"aes_annotate_{tag}_status"] = f"annotate_failed_rc_{last_rc}"
            out["aes_annotate_status"] = "partial_or_failed"
            continue

        parsed = _parse_perf_annotate(merged_text)
        out[f"aes_annotate_{tag}_status"] = "ok"
        out[f"aes_{tag}_annotate_symbols"] = ",".join(ok_symbols)
        out[f"aes_{tag}_annotate_rows"] = parsed["parsed_rows"]
        out[f"aes_{tag}_annotate_top12"] = parsed["hotspot_top12"]
        out[f"aes_{tag}_aesenc_pct_sum"] = parsed["aesenc_pct_sum"]
        out[f"aes_{tag}_lookup_load_pct_sum"] = parsed["lookup_load_pct_sum"]
        out[f"aes_{tag}_annotate_path"] = str(annotate_txt)

    noasm_lookup = float(out.get("aes_noasm_lookup_load_pct_sum", "0") or "0")
    noasm_aesenc = float(out.get("aes_noasm_aesenc_pct_sum", "0") or "0")
    aesni_lookup = float(out.get("aes_aesni_lookup_load_pct_sum", "0") or "0")
    aesni_aesenc = float(out.get("aes_aesni_aesenc_pct_sum", "0") or "0")

    if (
        out.get("aes_annotate_noasm_status") == "ok"
        and out.get("aes_annotate_aesni_status") == "ok"
    ):
        if noasm_lookup > 5.0 and noasm_aesenc < 1.0 and aesni_aesenc > 30.0:
            out["aes_path_inference"] = "ttable_vs_aesni_confirmed"
        else:
            out["aes_path_inference"] = "inconclusive_manual_check_needed"
    else:
        out["aes_path_inference"] = "incomplete"
    return out


def run_51a(args: argparse.Namespace) -> None:
    require_root("[!] run_51.py requires root. Use: sudo -E python3 src/scripts/run_51.py")
    outdir = (
        Path(args.outdir).resolve()
        if args.outdir
        else timestamped_outdir_ch5("exp5_1_a")
    )
    outdir.mkdir(parents=True, exist_ok=True)
    print_banner("Experiment 5.1-A: victim crypto behavior validation", outdir)

    ensure_artifacts(args.skip_build, outdir / "build_stage")
    ensure_runtime_paths()
    collect_host_facts(outdir)
    seed_51a_layout(outdir)

    vm_dir = outdir / "vm_validate"
    vm_dir.mkdir(parents=True, exist_ok=True)
    qemu_log = vm_dir / "qemu.log"
    debugcon = vm_dir / "debugcon.log"
    serial = vm_dir / "qemu_console.log"

    append = "console=ttyS0 rdinit=/init panic=-1 quiet probe_mode=crypto_validate"
    qemu_cmd = [
        "taskset",
        "-c",
        str(args.qemu_cpu),
        str(QEMU_BIN),
        "-enable-kvm",
        "-cpu",
        args.cpu_model,
        "-machine",
        "q35,smm=off",
        "-machine",
        "confidential-guest-support=sev0,vmport=off",
        "-machine",
        "memory-backend=ram1",
        "-smp",
        str(args.smp),
        "-m",
        str(args.mem),
        "-no-reboot",
        "-object",
        f"memory-backend-memfd,id=ram1,size={args.mem},share=true,prealloc=false",
        "-object",
        "sev-snp-guest,id=sev0,policy=0x30000,cbitpos=51,reduced-phys-bits=1",
        "-bios",
        str(OVMF_FD),
        "-kernel",
        str(GUEST_KERNEL),
        "-initrd",
        str(INITRAMFS),
        "-append",
        append,
        "-serial",
        f"file:{serial}",
        "-debugcon",
        f"file:{debugcon}",
        "-nographic",
        "-monitor",
        f"unix:{vm_dir / 'qemu.monitor'},server,nowait",
    ]

    proc = run_qemu_background(qemu_cmd, log_path=qemu_log, cwd=SRC_DIR, env=os.environ.copy())
    ok, failed_fast = wait_done(debugcon, args.timeout_s)
    stop_proc(proc, timeout_s=10.0)

    metrics = parse_crypto51_metrics(debugcon)
    metrics.update(collect_path_proofs())
    metrics.update(run_aes_annotate_profile(outdir, args.aes_profile_ops, args.perf_bin))
    metrics["run_completed"] = "1" if ok else "0"
    metrics["run_failed_fast"] = "1" if failed_fast else "0"
    metrics["generated_at"] = now()

    write_json(outdir / "metrics_51a.json", metrics)
    write_lines(
        outdir / "stats_51a.txt",
        [
            f"run_completed={metrics.get('run_completed', '0')}",
            f"aes_metric_type={metrics.get('aes_metric_type', metrics.get('aes_proxy_metric_type', 'unknown'))}",
            f"aes_perf_event_ok={metrics.get('aes_perf_event_ok', '-1')}",
            f"openssl_version={metrics.get('openssl_version', 'unknown')}",
            f"libgcrypt_176_version={metrics.get('libgcrypt_176_version', 'unknown')}",
            f"libgcrypt_178_version={metrics.get('libgcrypt_178_version', 'unknown')}",
            f"aes_ttable_defs={metrics.get('aes_ttable_defs', '-1')}",
            f"aes_ttable_refs={metrics.get('aes_ttable_refs', '-1')}",
            f"openssl_noasm_doc={metrics.get('openssl_noasm_doc', '-1')}",
            f"aesni_source_exists={metrics.get('aesni_source_exists', '-1')}",
            f"aes_noasm_misses_avg={metrics.get('aes_noasm_misses_avg', '-1')}",
            f"aes_aesni_misses_avg={metrics.get('aes_aesni_misses_avg', '-1')}",
            f"aes_noasm_metric_per_1k={metrics.get('aes_noasm_metric_per_1k', '-1')}",
            f"aes_aesni_metric_per_1k={metrics.get('aes_aesni_metric_per_1k', '-1')}",
            f"aes_noasm_perf_open_errno={metrics.get('aes_noasm_perf_open_errno', '0')}",
            f"aes_noasm_perf_reset_errno={metrics.get('aes_noasm_perf_reset_errno', '0')}",
            f"aes_noasm_perf_enable_errno={metrics.get('aes_noasm_perf_enable_errno', '0')}",
            f"aes_noasm_perf_read_errno={metrics.get('aes_noasm_perf_read_errno', '0')}",
            f"aes_aesni_perf_open_errno={metrics.get('aes_aesni_perf_open_errno', '0')}",
            f"aes_aesni_perf_reset_errno={metrics.get('aes_aesni_perf_reset_errno', '0')}",
            f"aes_aesni_perf_enable_errno={metrics.get('aes_aesni_perf_enable_errno', '0')}",
            f"aes_aesni_perf_read_errno={metrics.get('aes_aesni_perf_read_errno', '0')}",
            f"aes_annotate_status={metrics.get('aes_annotate_status', 'unknown')}",
            f"aes_annotate_perf_bin={metrics.get('aes_annotate_perf_bin', '')}",
            f"aes_annotate_perf_lookup={metrics.get('aes_annotate_perf_lookup', '')}",
            f"aes_path_inference={metrics.get('aes_path_inference', 'unknown')}",
            f"aes_noasm_lookup_load_pct_sum={metrics.get('aes_noasm_lookup_load_pct_sum', '-1')}",
            f"aes_noasm_aesenc_pct_sum={metrics.get('aes_noasm_aesenc_pct_sum', '-1')}",
            f"aes_noasm_annotate_symbols={metrics.get('aes_noasm_annotate_symbols', '')}",
            f"aes_aesni_lookup_load_pct_sum={metrics.get('aes_aesni_lookup_load_pct_sum', '-1')}",
            f"aes_aesni_aesenc_pct_sum={metrics.get('aes_aesni_aesenc_pct_sum', '-1')}",
            f"aes_aesni_annotate_symbols={metrics.get('aes_aesni_annotate_symbols', '')}",
            f"aes_noasm_annotate_top12={metrics.get('aes_noasm_annotate_top12', '')}",
            f"aes_aesni_annotate_top12={metrics.get('aes_aesni_annotate_top12', '')}",
            f"rsa_metric_source={metrics.get('rsa_metric_source', 'unknown')}",
            f"rsa_var_mean_cycles={metrics.get('rsa_var_mean_cycles', '-1')}",
            f"rsa_const_mean_cycles={metrics.get('rsa_const_mean_cycles', '-1')}",
            f"rsa_var_std_cycles={metrics.get('rsa_var_std_cycles', '-1')}",
            f"rsa_const_std_cycles={metrics.get('rsa_const_std_cycles', '-1')}",
            f"rsa_var_cv={metrics.get('rsa_var_cv', '-1')}",
            f"rsa_const_cv={metrics.get('rsa_const_cv', '-1')}",
            f"rsa_std_ratio={metrics.get('rsa_std_ratio', '-1')}",
            f"rsa_cv_ratio={metrics.get('rsa_cv_ratio', '-1')}",
            f"proof_guest_aes_noasm_exists={metrics.get('proof_guest_aes_noasm_exists', '0')}",
            f"proof_guest_aes_asm_exists={metrics.get('proof_guest_aes_asm_exists', '0')}",
            f"proof_guest_rsa_bench_exists={metrics.get('proof_guest_rsa_bench_exists', '0')}",
            f"proof_openssl_noasm_lib_exists={metrics.get('proof_openssl_noasm_lib_exists', '0')}",
            f"proof_openssl_asm_lib_exists={metrics.get('proof_openssl_asm_lib_exists', '0')}",
            f"proof_aes_noasm_has_aesni_symbol={metrics.get('proof_aes_noasm_has_aesni_symbol', '0')}",
            f"proof_aes_noasm_has_vpaes_symbol={metrics.get('proof_aes_noasm_has_vpaes_symbol', '0')}",
            f"proof_aes_noasm_has_aes_encrypt={metrics.get('proof_aes_noasm_has_aes_encrypt', '0')}",
            f"proof_noasm_lib_has_aesni_symbol={metrics.get('proof_noasm_lib_has_aesni_symbol', '0')}",
            f"proof_noasm_lib_has_vpaes_symbol={metrics.get('proof_noasm_lib_has_vpaes_symbol', '0')}",
            f"proof_aes_asm_has_aesni_symbol={metrics.get('proof_aes_asm_has_aesni_symbol', '0')}",
            f"proof_aes_asm_has_vpaes_symbol={metrics.get('proof_aes_asm_has_vpaes_symbol', '0')}",
            f"proof_aes_asm_has_aes_encrypt={metrics.get('proof_aes_asm_has_aes_encrypt', '0')}",
            f"proof_asm_lib_has_aesni_symbol={metrics.get('proof_asm_lib_has_aesni_symbol', '0')}",
            f"proof_asm_lib_has_vpaes_symbol={metrics.get('proof_asm_lib_has_vpaes_symbol', '0')}",
            f"proof_rsa_has_var_api_symbol={metrics.get('proof_rsa_has_var_api_symbol', '0')}",
            f"proof_rsa_has_const_api_symbol={metrics.get('proof_rsa_has_const_api_symbol', '0')}",
        ],
    )

    write_json(
        outdir / "meta_51a.json",
        {
            "experiment": "5.1-A",
            "cmdline_probe_mode": "crypto_validate",
            "qemu_cpu": args.qemu_cpu,
            "cpu_model": args.cpu_model,
            "host_cpu": args.host_cpu,
            "mem": args.mem,
            "smp": args.smp,
            "timeout_s": args.timeout_s,
            "aes_profile_ops": args.aes_profile_ops,
            "perf_bin": args.perf_bin,
            "qemu_log": str(qemu_log),
            "debugcon_log": str(debugcon),
            "serial_log": str(serial),
            "run_completed": ok,
        },
    )

    print("\n=== 5.1-A completed ===")
    print(f"data dir: {outdir}")
    if failed_fast:
        print("[warn] CRYPTO51 reported error; run stopped early. Check debugcon metrics 'error=' field.")
    elif not ok:
        print("[warn] run timeout or missing CRYPTO51_DONE; check debugcon/qemu logs.")


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Experiment 5.1-A runner (guest crypto behavior validation)."
    )
    ap.add_argument("--outdir", default="")
    ap.add_argument("--skip-build", action="store_true")
    ap.add_argument("--qemu-cpu", type=int, default=32)
    ap.add_argument("--cpu-model", default="host,pmu=on")
    ap.add_argument("--host-cpu", type=int, default=33)
    ap.add_argument("--mem", default="4G")
    ap.add_argument("--smp", default="1")
    ap.add_argument("--timeout-s", type=int, default=180)
    ap.add_argument("--aes-profile-ops", type=int, default=10_000_000)
    ap.add_argument(
        "--perf-bin",
        default=str(AMDSEV_DIR / "linux" / "host" / "tools" / "perf" / "perf"),
    )
    args = ap.parse_args()
    run_51a(args)


if __name__ == "__main__":
    main()
