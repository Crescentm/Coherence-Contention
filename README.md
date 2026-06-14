# Coherence-Contention

Reproducing coherence- and contention-based cache side-channel signals on AMD SEV-SNP.

This repository contains the source code, experiment scripts, and analysis utilities for coherence-contention experiments around AMD SEV/SNP environments.

The repository is intentionally source-only. Large external trees, VM images, build outputs, and raw experiment results are not included.

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

Before running experiments, fetch or build the required external components separately, then update paths in the scripts as needed.

## Not Included

- Raw experiment outputs from `result/`.
- Build products from `build/`.
- VM images, initramfs images, kernel module binaries, and performance data.
- Local virtual environments.
- Chat logs or local assistant metadata.
- Large third-party source checkouts.

## Open-Source Readiness

See `OPEN_SOURCE_NOTES.md` for items that should be reviewed before publishing publicly.
