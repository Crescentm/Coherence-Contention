# C Code Structure (Host, Guest, and Kernel Components)

This document explains the structure of all C source files under `src/`, with focus on ownership, runtime flow, and how data moves between guest and host.

## 1) Top-Level Runtime Architecture

The project uses a split design:

- Guest userspace program (`guest_probe.c`) drives experiment behavior inside the VM.
- Host logic is injected into QEMU with `LD_PRELOAD` (`host_runner_preload.c` + mode files).
- Shared-memory synchronization is done through one decrypted SNP shared page (`struct sync_mailbox` in `host_runner_preload_shared.h`).
- Guest kernel module (`kmod_guest/snp_sync_kmod.c`) allocates and exposes the shared page.
- Host kernel module (`kmod/hpa_reader_kmod.c`) provides controlled host-side mapping/read helpers for HPA-based access.

Debug log output is used only to bootstrap the shared page GPA. Experiment metadata and synchronization happen through the shared page mailbox for non-blind modes.

## 2) Host-Side Preload Layer

### `host_runner_preload.c`

This file is now intentionally small. It only:

- Runs as a constructor when the shared library is injected.
- Prevents duplicate startup with `.hr_preload.lock`.
- Dispatches by `HR_MODE` to a mode-specific thread entry.

It does not contain heavy mode logic anymore.

### `host_runner_modes/common_runtime.c`

This file contains shared host runtime helpers reused by all preload modes:

- CPU pinning and file wait helpers.
- Counter/sequence waiting primitives (`wait_sync_guest_seq`, `wait_phase_guest_seq`, ack signaling).
- Mailbox readiness/config handshake (`wait_mailbox_magic`, `wait_guest_cfg`).
- KVM fd discovery and GPA/HPA translation.
- Shared page mapping (`map_shared_counter_page`), with HVA-first fast path in preload context.
- Host-side line measurement helper (`measure_line_ex`).
- Recursive directory creation and debug log line parsing (`wait_probe_shared_gpa`).

### `host_runner_modes/mode_pc.c`

Contains full Prime+Count implementation (`hr_mode_pc_impl`) and the `hr_main_thread_pc` entry wrapper, including:

- Eviction set construction from host virtual pages by physical set matching.
- Prime/probe collection with miss-count signal extraction.
- Forced-control diagnostics and output generation.
- Shared-page synchronization with guest.

### `host_runner_preload_pc.c`

Legacy placeholder file kept only for compatibility with old references/editor tabs. Active Prime+Count logic now lives in `host_runner_modes/mode_pc.c`.

## 3) Mode Files (`src/host_runner_modes/`)

Each mode has its own implementation file plus a thread-entry wrapper:

- `mode_single.c`
  - One victim-line experiment path.
  - Reads config from shared mailbox.
  - Performs per-line host probing with guest-host bidirectional sync.
  - Writes `line_matrix_row.csv`, `meta.txt`, and optional raw trace.

- `mode_all.c`
  - Multi-phase full sweep mode.
  - Uses phase channels (`phase_seq/phase_ack`) for row-level orchestration.
  - Uses sample channels (`guest_seq/host_seq`) for per-repetition sync.
  - Writes per-victim-line/per-page outputs and completion marker.

- `mode_contention.c`
  - Contention-focused mode with high repetition count.
  - Uses bidirectional sync (`guest_seq` + `host_seq`) per sample.
  - Outputs H1/H0 raw cycle traces and metadata.

- `mode_toggle.c`
  - Cipher-toggle inspection mode.
  - Gets static parameters from mailbox config.
  - Consumes toggle event stream from debug log (`SNP_TOGGLE` markers).
  - Reads line content in multiple modes via `hpa_reader` and computes fingerprints.

- `mode_pc.c`
  - Prime+Count mode implementation.
  - Builds eviction sets, performs forced-control diagnostics, and runs synchronized H1/H0 counting.
  - Writes Prime+Count raw outputs and metadata.

- `mode_blind.c`
  - Blind mode exception path (no mailbox synchronization loop).
  - Parses target GPA from debug log and performs unsynchronized sampling.

## 4) Shared Protocol Definition

### `host_runner_preload_shared.h`

This header is the protocol contract for both guest and host:

- Defines `struct sync_mailbox` layout (cache-line aligned channels).
- Defines constants for phase and cfg modes.
- Defines KVM ioctl structs used by host userspace.
- Exposes host helper/mode function prototypes when building preload code.

Key channels in mailbox:

- `guest_seq` / `host_seq`: per-sample bidirectional sync.
- `phase_seq` / `phase_ack`: per-phase orchestration (mainly all-mode).
- `cfg_ready_seq` / `cfg_ack_seq` + `cfg_*`: one-shot guest-to-host config publish/ack.
- `phase_magic`: mailbox initialization guard.

## 5) Guest Userspace

### `guest_probe.c`

Main guest experiment executable. Responsibilities:

- Reads command-line/config mode.
- Allocates target pages and computes GPAs.
- Initializes debug console output for bootstrap lines.
- Maps `/dev/snp_sync` shared page and initializes mailbox state.
- Publishes mode-specific config to mailbox (`cfg_*` + ready/ack handshake).
- Runs experiment loops and synchronizes with host by mailbox sequence channels (except blind mode behavior by design).

This file is the guest control plane for all experiment variants.

## 6) Host Standalone Binary

### `host_runner.c`

A deprecated placeholder executable kept for compatibility with old scripts/build paths. It prints a deprecation message and exits. Active host logic is preload-based.

## 7) Kernel Modules

### `kmod_guest/snp_sync_kmod.c`

Guest-side kernel module:

- Allocates one page.
- Marks it decrypted/shared for SNP (`set_memory_decrypted`).
- Exposes `/dev/snp_sync`:
  - `ioctl` to return shared page GPA.
  - `mmap` for guest userspace mailbox access.

### `kmod/hpa_reader_kmod.c`

Host-side kernel module:

- Exposes `/dev/hpa_reader_cohere`.
- Supports:
  - Read requests from given HPA in multiple view modes.
  - Set-page + measure-line operations.
  - Shared-page setup + `mmap` path for host userspace polling/mapping.
- Provides host-side mapping utility needed when direct HVA path is unavailable.

### `kmod_cbit/dev_cbit.c`

Utility kernel module for host-only C-bit mapping experiments via `/dev/cbit_mmap`.

## 8) Utility / Validation Programs

- `tools/fr_verify.c`
  - Flush+Reload feasibility validation helper with logging.

- `exp41c_host_only.c`
  - Host-only C-bit eviction verification program for experiment 4.1-C style checks.

## 9) Auto-Generated Kernel Build Artifacts

These files are generated by the Linux kernel module build system and should not be treated as hand-maintained architecture sources:

- `kmod/hpa_reader_kmod.mod.c`
- `kmod_guest/snp_sync_kmod.mod.c`
- `kmod_cbit/dev_cbit.mod.c`

## 10) Build Wiring

`Makefile` builds the preload shared library from:

- `host_runner_preload.c` (constructor dispatcher),
- `host_runner_modes/common_runtime.c` (shared helpers),
- `host_runner_modes/mode_*.c` (mode implementations and wrappers).

This keeps mode logic physically separated and avoids concentrating all functionality in a single preload source file.
