#!/usr/bin/env bash
set -euo pipefail

AMDSEV_DIR="${AMDSEV_DIR:-<AMDSEV_DIR>}"
LINUX_TREE="${1:-$AMDSEV_DIR/linux/host}"

if [[ ! -d "$LINUX_TREE/tools/perf" ]]; then
  echo "[err] perf source dir not found: $LINUX_TREE/tools/perf" >&2
  exit 1
fi

echo "[info] building perf from: $LINUX_TREE/tools/perf"
make -C "$LINUX_TREE/tools/perf" -j"$(nproc)" \
  NO_LIBTRACEEVENT=1 \
  NO_LIBBPF=1 \
  NO_LIBPERL=1 \
  NO_LIBPYTHON=1 \
  NO_SLANG=1 \
  NO_LIBNUMA=1 \
  NO_LIBZSTD=1 \
  NO_LIBBABELTRACE=1 \
  NO_LIBCAPSTONE=1

PERF_BIN="$LINUX_TREE/tools/perf/perf"
if [[ ! -x "$PERF_BIN" ]]; then
  echo "[err] build finished but perf binary missing: $PERF_BIN" >&2
  exit 1
fi

echo "[ok] perf ready: $PERF_BIN"
"$PERF_BIN" --version || true

echo
echo "Use it in 5.1:"
echo "  sudo -E python3 <COHERE_REPO>/src/scripts/run_51.py --perf-bin $PERF_BIN"
