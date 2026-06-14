#!/usr/bin/env python3
"""
Experiment 4.2-B (batch-ioctl variant): unsynchronised DRAM contention measurement.

Instead of the old LD_PRELOAD+mailbox path (one KVM_AMD_READ_GPA per guest sync
event), this script drives the VM through the nptctl Unix-socket bridge and calls
KVM_AMD_READ_GPA_BATCH to acquire `--batch-size` TSC samples in a single kernel
round-trip.

H0 (baseline)  : probe `other_page_gpa`  – a GPA the guest never touches
H1 (contention): probe `page_gpa`        – the page the guest loops on

Because there is no explicit synchronisation the host samples the cache line
freely while the guest's AES thread races for the same DRAM row, producing the
contention spikes that distinguish H1 from H0.

Output (same layout as run_42b.py so exp42b_analysis.py can consume it):
  <outdir>/raw_h0_cycles.csv   – one TSC-delta value per line
  <outdir>/raw_h1_cycles.csv
  <outdir>/meta.txt
  <outdir>/contention_done.txt
"""
from __future__ import annotations

import argparse
import csv
import os
import statistics
import threading
import time
from pathlib import Path

from experiment_common import (
    chown_to_sudo_user,
    ensure_artifacts,
    print_banner,
    require_root,
    stop_proc,
    timestamped_outdir,
    RESULT_CH4,
    SRC_DIR,
)
from run_53 import (
    KVM_AMD_READ_GPA_MODE_CIPHERTEXT_NOCACHE,
    NptCtlClient,
    aes_request_async_finish,
    aes_request_async_poll,
    aes_request_async_start,
    ioctl_gpa_to_hpa,
    ioctl_read_gpa_tsc_batch,
    launch_victim_vm,
    load_scan_range,
    maybe_sync_oracle_from_range_json,
    npt_discovery,
    select_target_page,
    wait_nptctl_ready,
    wait_vm_ready,
)


PAGE_SZ = 4096


def write_csv(path: Path, samples: list[int]) -> None:
    with path.open("w", newline="") as fp:
        wr = csv.writer(fp)
        wr.writerow(["cycles"])
        for v in samples:
            wr.writerow([v])


def collect_batch_samples(
    vm_ctl: NptCtlClient,
    gpa: int,
    total: int,
    batch_size: int,
    mode: int,
    inter_batch_sleep_us: float,
) -> list[int]:
    """Accumulate `total` TSC samples from `gpa` using batch ioctl."""
    out: list[int] = []
    while len(out) < total:
        want = min(batch_size, total - len(out))
        try:
            ts = ioctl_read_gpa_tsc_batch(vm_ctl, gpa, mode=mode,
                                          nr_samples=want, flags=0)
            out.extend(ts)
        except Exception as exc:
            print(f"[warn] batch read gpa=0x{gpa:x} failed: {exc}")
            time.sleep(0.001)
            continue
        if inter_batch_sleep_us > 0.0:
            time.sleep(inter_batch_sleep_us / 1_000_000.0)
    return out[:total]


def collect_sync_batch_samples(
    vm_ctl: NptCtlClient,
    hot_gpa: int,
    cold_gpa: int,
    rounds: int,
    batch_size: int,
    mode: int,
    host: str,
    aes_port: int,
    sock_timeout_s: float,
    aes_delay_us: float = 200.0,
) -> tuple[list[int], list[int]]:
    """Collect H1 and H0 samples using a "batch-first, AES-second" strategy.

    H1 — batch ioctl starts first, AES fires mid-batch:
      Two threads share a Barrier so they start together:
        Thread A: issues ioctl_read_gpa_tsc_batch (blocks in kernel for
                  batch_size × NOCACHE probes, total ~batch_size × DRAM_lat).
        Thread B: sleeps aes_delay_us then fires one synchronous AES request.
      aes_delay_us is tuned so AES executes inside the batch window.
      Contention samples appear in Thread A's TSC array at the moments
      the guest T-table access races the host DRAM probe.

    H0 — same batch ioctl against hot_gpa with NO AES triggered:
      One batch issued while guest is idle → pure NOCACHE floor latency.

    Both H0 and H1 probe the same hot_gpa; the only difference is whether
    the guest concurrently races the host for the same DRAM row.
    """
    h1: list[int] = []
    h0: list[int] = []
    aes_delay_s = aes_delay_us / 1_000_000.0

    for i in range(rounds):
        pt = os.urandom(16)

        # ── H1: batch + concurrent AES via two threads ─────────────────────
        result_h1: list[int] = []
        exc_box: list[Exception] = []

        def _batch_thread() -> None:
            try:
                ts = ioctl_read_gpa_tsc_batch(vm_ctl, hot_gpa,
                                               mode=mode,
                                               nr_samples=batch_size,
                                               flags=0)
                result_h1.extend(ts)
            except Exception as e:
                exc_box.append(e)

        def _aes_thread() -> None:
            time.sleep(aes_delay_s)  # let batch enter kernel first
            try:
                aes_request_async_finish(
                    aes_request_async_start(host, aes_port, pt,
                                             timeout_s=sock_timeout_s)
                )
            except Exception:
                pass

        barrier = threading.Barrier(2)

        def _batch_thread_b() -> None:
            barrier.wait()
            _batch_thread()

        def _aes_thread_b() -> None:
            barrier.wait()
            _aes_thread()

        t_batch = threading.Thread(target=_batch_thread_b, daemon=True)
        t_aes   = threading.Thread(target=_aes_thread_b,  daemon=True)
        t_batch.start()
        t_aes.start()
        t_batch.join(timeout=sock_timeout_s + 1.0)
        t_aes.join(timeout=sock_timeout_s + 1.0)

        if exc_box:
            print(f"[warn] H1 batch error: {exc_box[0]}")
        else:
            h1.extend(result_h1)

        # ── H0: same batch, no AES ─────────────────────────────────────────
        try:
            ts0 = ioctl_read_gpa_tsc_batch(vm_ctl, hot_gpa,
                                            mode=mode,
                                            nr_samples=batch_size,
                                            flags=0)
            h0.extend(ts0)
        except Exception as exc:
            print(f"[warn] H0 batch error: {exc}")

        if (i + 1) % 200 == 0:
            print(f"  [sync] {i+1}/{rounds} rounds  "
                  f"h1={len(h1)}  h0={len(h0)}")

    return h1, h0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="4.2-B batch-ioctl: unsynchronised DRAM contention probe"
    )
    # Target
    ap.add_argument("--suspected-range-json", default="",
                    help="JSON file produced by the discovery phase")
    ap.add_argument("--scan-start-gpa", default="",
                    help="Manual scan start GPA (hex/dec), overrides JSON")
    ap.add_argument("--scan-end-gpa", default="",
                    help="Manual scan end GPA (hex/dec), overrides JSON")
    ap.add_argument("--te0-inpage-offset", default="",
                    help="te0 offset within page (hex/dec), overrides JSON")
    ap.add_argument("--force-te-page-gpa", default="",
                    help="Skip discovery, force this page GPA as target")
    ap.add_argument("--force-other-page-gpa", default="",
                    help="Force baseline GPA (H0); if omitted picks first page "
                         "≥16 pages away from page_gpa that did not appear in NPT discovery")

    # Sampling
    ap.add_argument("--samples", type=int, default=100000,
                    help="Total TSC samples to collect per GPA (H0 and H1 each)")
    ap.add_argument("--batch-size", type=int, default=64,
                    help="nr_samples per KVM_AMD_READ_GPA_BATCH call")
    ap.add_argument("--inter-batch-sleep-us", type=float, default=0.0,
                    help="Optional sleep between batch calls (microseconds, unsync mode only)")
    ap.add_argument("--mode", type=int,
                    default=KVM_AMD_READ_GPA_MODE_CIPHERTEXT_NOCACHE,
                    help="KVM read-GPA mode (2=ciphertext-nocache, 4=ciphertext-cacheable)")

    # Synchronised mode
    ap.add_argument("--sync", action="store_true",
                    help="Enable AES-trigger synchronisation: continuously probe "
                         "hot line while AES executes, cold line when idle")
    ap.add_argument("--sync-rounds", type=int, default=0,
                    help="Number of AES-trigger rounds in sync mode; "
                         "0 = auto (samples // batch_size)")

    # Discovery tuning (passed through to npt_discovery / select_target_page)
    ap.add_argument("--discover-rounds", type=int, default=8)
    ap.add_argument("--trigger-requests-per-round", type=int, default=8)
    ap.add_argument("--baseline-wait-ms", type=int, default=2)
    ap.add_argument("--confirm-pages", type=int, default=8)
    ap.add_argument("--confirm-line-reps", type=int, default=8)

    # VM / infra
    ap.add_argument("--qemu-cpu", type=int, default=32)
    ap.add_argument("--cpu-model", default="host,pmu=on")
    ap.add_argument("--smp", type=int, default=1)
    ap.add_argument("--mem", default="4G")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--aes-port", type=int, default=9000)
    ap.add_argument("--rsa-port", type=int, default=9001)
    ap.add_argument("--vm-ready-timeout-s", type=int, default=180)
    ap.add_argument("--sock-timeout-s", type=float, default=5.0)
    ap.add_argument("--guest-extra-cmdline", default="")

    ap.add_argument("--skip-build", action="store_true")
    ap.add_argument("--outdir", default="")
    return ap


def main() -> None:
    ap = build_parser()
    args = ap.parse_args()
    require_root("run_42b_batch.py must be run as root (sudo -E)")

    outdir = (
        Path(args.outdir).resolve()
        if args.outdir
        else timestamped_outdir("exp4_2_b_batch", RESULT_CH4)
    )
    outdir.mkdir(parents=True, exist_ok=True)
    print_banner("4.2-B batch-ioctl: DRAM contention (sync/unsync)", outdir)

    maybe_sync_oracle_from_range_json(args)
    ensure_artifacts(bool(args.skip_build), outdir / "build_stage")

    scan_start_gpa, scan_end_gpa, te0_inpage_offset = load_scan_range(args)

    vm_dir = outdir / "vm"
    proc = None
    vm_ctl = None
    try:
        proc, npt_sock = launch_victim_vm(args, vm_dir)

        print("[vm] waiting for nptctl socket...")
        if not wait_nptctl_ready(npt_sock, timeout_s=args.vm_ready_timeout_s):
            raise SystemExit(f"[vm] nptctl not ready: {npt_sock}")
        print("[vm] waiting for AES service...")
        if not wait_vm_ready(args.host, args.aes_port,
                             timeout_s=args.vm_ready_timeout_s):
            raise SystemExit("[vm] AES service not ready")

        vm_ctl = NptCtlClient(npt_sock, timeout_s=float(args.sock_timeout_s))
        vm_ctl.connect()
        vm_ctl.ping()
        print("[vm] nptctl connected")

        # ── resolve target GPAs ────────────────────────────────────────────
        # H1 probe target: the specific 64B cache line that the guest's AES
        # loop accesses (te0_gpa aligned down to LINE_SZ).  Using the page
        # base address is wrong — in NOCACHE mode the ioctl maps exactly the
        # requested address, so probing line 0 while the guest touches line 62
        # produces no contention signal.
        LINE_SZ = 64
        if args.force_te_page_gpa:
            from run_53 import parse_u64
            te_page_gpa = parse_u64(args.force_te_page_gpa) & ~(PAGE_SZ - 1)
            # Without te0_gpa info, fall back to page base (user must supply
            # --force-other-page-gpa and pick the right line manually).
            te0_gpa = te_page_gpa
        else:
            ranking = npt_discovery(vm_ctl, args,
                                    scan_start_gpa, scan_end_gpa, outdir)
            if not ranking:
                raise SystemExit("[discover] empty NPT discovery result")
            selected = select_target_page(vm_ctl, ranking, args, outdir,
                                          te0_inpage_offset=te0_inpage_offset)
            te_page_gpa = int(selected["te_page_gpa"])
            te0_gpa = int(selected["te0_gpa"])

        # Align te0_gpa down to a 64B boundary → the hot cache line
        page_gpa = te0_gpa & ~(LINE_SZ - 1)
        print(f"[cfg] te0_gpa=0x{te0_gpa:x}  hot_line_gpa=0x{page_gpa:x}"
              f"  (line {(page_gpa - (te_page_gpa & ~(PAGE_SZ-1))) // LINE_SZ}"
              f" within page)")

        if args.force_other_page_gpa:
            from run_53 import parse_u64
            other_page_gpa = parse_u64(args.force_other_page_gpa) & ~(LINE_SZ - 1)
        else:
            # H0 cold line: a 64B line at least 256 cache lines (16 KB) away
            # from the hot line, on a page that did not appear in NPT discovery.
            # We stay cache-line-aligned throughout.
            import json as _json
            active_pages: set[int] = set()
            try:
                rank_json = outdir / "discovery" / "npt_page_ranking.json"
                if rank_json.exists():
                    rdata = _json.loads(rank_json.read_text())
                    for entry in rdata.get("ranking", []):
                        active_pages.add(int(entry["page_gpa"]) & ~(PAGE_SZ - 1))
            except Exception:
                pass
            active_pages.add(te_page_gpa & ~(PAGE_SZ - 1))

            COLD_MIN_LINES = 256  # ≥ 16 KB gap from hot line
            candidate = (page_gpa + COLD_MIN_LINES * LINE_SZ) & ~(LINE_SZ - 1)
            while (candidate & ~(PAGE_SZ - 1)) in active_pages:
                candidate += PAGE_SZ  # skip the whole active page
            other_page_gpa = candidate
            print(f"[cfg] cold_line_gpa=0x{other_page_gpa:x}"
                  f"  (+{(other_page_gpa - page_gpa) // LINE_SZ} lines from hot,"
                  f" skipped {len(active_pages)} active pages)")

        print(f"[cfg] page_gpa=0x{page_gpa:x}  other_page_gpa=0x{other_page_gpa:x}")
        print(f"[cfg] samples={args.samples}  batch_size={args.batch_size}"
              f"  mode={args.mode}")

        # ── translate to HPA for metadata ─────────────────────────────────
        try:
            hpa_info = ioctl_gpa_to_hpa(vm_ctl, page_gpa)
            page_hpa = int(hpa_info["hpa"])
        except Exception:
            page_hpa = 0
        try:
            other_hpa_info = ioctl_gpa_to_hpa(vm_ctl, other_page_gpa)
            other_hpa = int(other_hpa_info["hpa"])
        except Exception:
            other_hpa = 0

        # ── warm-up: drain TLB / cache state ──────────────────────────────
        WARMUP_BATCHES = 8
        print("[warmup] draining cache state...")
        for _ in range(WARMUP_BATCHES):
            try:
                ioctl_read_gpa_tsc_batch(vm_ctl, page_gpa, mode=args.mode,
                                         nr_samples=args.batch_size, flags=0)
                ioctl_read_gpa_tsc_batch(vm_ctl, other_page_gpa, mode=args.mode,
                                         nr_samples=args.batch_size, flags=0)
            except Exception:
                pass

        # ── collect samples ────────────────────────────────────────────────
        if args.sync:
            rounds = args.sync_rounds if args.sync_rounds > 0 \
                else max(1, args.samples // args.batch_size)
            print(f"[sync] AES-trigger mode: {rounds} rounds × batch_size={args.batch_size}")
            t0 = time.perf_counter()
            h1, h0 = collect_sync_batch_samples(
                vm_ctl,
                hot_gpa=page_gpa,
                cold_gpa=other_page_gpa,
                rounds=rounds,
                batch_size=args.batch_size,
                mode=args.mode,
                host=args.host,
                aes_port=args.aes_port,
                sock_timeout_s=args.sock_timeout_s,
            )
            t1 = time.perf_counter()
            print(f"[sync] done in {t1-t0:.1f}s  "
                  f"h1={len(h1)} median={statistics.median(h1) if h1 else 'n/a':.0f}  "
                  f"h0={len(h0)} median={statistics.median(h0) if h0 else 'n/a':.0f}")
            sync_label = "batch-ioctl-sync-nocache"
        else:
            # ── collect H1 (hot cache line – guest is actively accessing it) ───
            print(f"[H1] collecting {args.samples} samples from hot_line_gpa=0x{page_gpa:x} ...")
            t0 = time.perf_counter()
            h1 = collect_batch_samples(
                vm_ctl, page_gpa,
                total=args.samples,
                batch_size=args.batch_size,
                mode=args.mode,
                inter_batch_sleep_us=args.inter_batch_sleep_us,
            )
            t1 = time.perf_counter()
            print(f"[H1] done in {t1-t0:.1f}s  "
                  f"median={statistics.median(h1):.0f}  "
                  f"mean={statistics.fmean(h1):.0f}")

            # ── collect H0 (cold cache line – guest never accesses it) ──────────
            print(f"[H0] collecting {args.samples} samples from cold_line_gpa=0x{other_page_gpa:x} ...")
            t0 = time.perf_counter()
            h0 = collect_batch_samples(
                vm_ctl, other_page_gpa,
                total=args.samples,
                batch_size=args.batch_size,
                mode=args.mode,
                inter_batch_sleep_us=args.inter_batch_sleep_us,
            )
            t1 = time.perf_counter()
            print(f"[H0] done in {t1-t0:.1f}s  "
                  f"median={statistics.median(h0):.0f}  "
                  f"mean={statistics.fmean(h0):.0f}")
            sync_label = "batch-ioctl-nocache"

        # ── write output ───────────────────────────────────────────────────
        write_csv(outdir / "raw_h1_cycles.csv", h1)
        write_csv(outdir / "raw_h0_cycles.csv", h0)

        meta_lines = [
            f"mode={sync_label}",
            f"te0_gpa=0x{te0_gpa:x}",
            f"hot_line_gpa=0x{page_gpa:x}",
            f"hot_line_hpa=0x{page_hpa:x}",
            f"cold_line_gpa=0x{other_page_gpa:x}",
            f"cold_line_hpa=0x{other_hpa:x}",
            f"te_page_gpa=0x{te_page_gpa:x}",
            f"samples={args.samples}",
            f"batch_size={args.batch_size}",
            f"inter_batch_sleep_us={args.inter_batch_sleep_us}",
            f"kvm_mode={args.mode}",
            f"sync={int(args.sync)}",
            f"sync_rounds={args.sync_rounds}",
            f"h1_collected={len(h1)}",
            f"h0_collected={len(h0)}",
            f"h1_median={statistics.median(h1) if h1 else 'n/a'}",
            f"h0_median={statistics.median(h0) if h0 else 'n/a'}",
            f"delta_median={statistics.median(h1)-statistics.median(h0) if h1 and h0 else 'n/a'}",
        ]
        (outdir / "meta.txt").write_text("\n".join(meta_lines) + "\n")
        (outdir / "contention_done.txt").write_text(
            f"collected={len(h1)}\nmode={sync_label}\n"
        )

        print("\n=== 4.2-B batch done ===")
        print(f"data dir: {outdir}")
        print(f"analysis: python3 {SRC_DIR / 'analyze' / 'exp42b_analysis.py'}"
              f" --dir {outdir} --out {outdir}")

    finally:
        if vm_ctl is not None:
            vm_ctl.close()
        if proc is not None:
            stop_proc(proc, timeout_s=5.0)
        chown_to_sudo_user(outdir)


if __name__ == "__main__":
    main()
