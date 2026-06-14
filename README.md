# Coherence-Contention

Reproducing coherence- and contention-based cache side-channel signals on AMD SEV-SNP.

This repository contains the source code, experiment scripts, and analysis utilities for coherence-contention experiments around AMD SEV/SNP environments.

The repository is intentionally source-only. Large external trees, VM images, build outputs, and raw experiment results are not included.

## Code Background

The code implements a split host/guest experiment framework for studying cache-coherence and memory-contention side-channel signals in SEV-SNP VMs.

At runtime, the guest executes controlled victim/probe behavior, while host-side logic is injected into QEMU with `LD_PRELOAD`. The host and guest synchronize through one SNP shared page exposed by the guest kernel module. That shared page contains a small mailbox protocol used for experiment configuration, per-sample handshakes, phase control, and acknowledgements.

The active host implementation is organized around preload modes:

- `host_runner_preload.c` starts the preload thread and dispatches by `HR_MODE`.
- `host_runner_modes/common_runtime.c` contains shared runtime helpers for CPU pinning, mailbox synchronization, KVM fd discovery, GPA/HPA translation, page mapping, and line measurement.
- `host_runner_modes/mode_*.c` contains individual experiment implementations such as single-line probing, full sweeps, contention, toggle tracing, Prime+Count, and blind sampling.

The guest side is centered on `guest_probe.c`, which allocates target pages, computes GPAs, publishes mode configuration through the mailbox, and drives synchronized access loops. Additional guest programs provide AES/RSA victims, crypto validation, toggle workloads, and benchmark harnesses.

Kernel support is split into:

- `kmod_guest/snp_sync_kmod.c`: allocates a decrypted/shared SNP page and exposes it through `/dev/snp_sync` for guest userspace.
- `kmod/hpa_reader_kmod.c`: provides host-side HPA/GPA read and measurement helpers.
- `kmod_cbit/dev_cbit.c`: supports host-only C-bit mapping experiments.

The main signal families are:

- Coherence signal: the guest touches a target cache line, then the host measures ciphertext-side access latency shortly after the synchronized access.
- Contention signal: the guest forces memory traffic around a target line, while the host measures cache-bypassing access latency against H0/H1 paths.
- Prime+Count: the host builds eviction sets and collects synchronized miss-count signals.
- Crypto victim modes: AES/RSA guests provide controlled workloads for key-recovery and defense experiments.

## Contents

- `*.c`: host and guest experiment programs.
- `host_runner_modes/`: host runner mode implementations.
- `kmod/`, `kmod_guest/`, `kmod_cbit/`: kernel module sources.
- `scripts/`: experiment orchestration scripts.
- `analyze/`: result analysis scripts.
- `tools/`: build and verification helpers.
- `docs/`, `require/`, `report/`: notes and reproduction documentation.
- `latex/`: thesis/report source and plot-generation helpers.

## External Dependencies

The original working tree used external projects such as AMDSEV, SEV-Step, OpenSSL, and libgcrypt. These are not vendored here to keep the repository small and auditable.

Before running experiments, fetch or build the required external components separately, then update paths in the scripts as needed. Several scripts expect an AMDSEV/KVM tree with out-of-tree support for GPA-to-HPA translation and host-side encrypted-memory reads.

## Not Included

- Raw experiment outputs from `result/`.
- Build products from `build/`.
- VM images, initramfs images, kernel module binaries, and performance data.
- Local virtual environments.
- Chat logs or local assistant metadata.
- Large third-party source checkouts.

## Notes

- Some scripts are research prototypes and may require path updates, privileged execution, kernel-module loading, or specific SEV-SNP host configuration.
- The RSA private key embedded in `guest_victim_rsa.c` is an experiment fixture, not an operational secret.
- Raw result directories are intentionally excluded; use `analyze/` and `latex/picgen/` to regenerate figures from reproduced runs.
