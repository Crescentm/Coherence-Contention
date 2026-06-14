#!/bin/bash
set -euo pipefail

SRC=""
OUT=""
MODE="asm"
CC_BIN="${CC:-musl-gcc}"
JOBS="${JOBS:-$(nproc)}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --src) SRC="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --mode) MODE="$2"; shift 2 ;;
    --cc) CC_BIN="$2"; shift 2 ;;
    --jobs) JOBS="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 1 ;;
  esac
done

if [[ -z "$SRC" || -z "$OUT" ]]; then
  echo "usage: $0 --src <openssl-src-dir> --out <build-dir> [--mode asm|noasm] [--cc musl-gcc] [--jobs N]" >&2
  exit 1
fi

if [[ ! -d "$SRC" ]]; then
  echo "error: source dir not found: $SRC" >&2
  exit 1
fi

mkdir -p "$OUT"
rsync -a --delete "$SRC"/ "$OUT"/

pushd "$OUT" >/dev/null

CONF_FLAGS=(
  linux-x86_64
  no-shared
  no-tests
  no-module
  no-apps
  no-secure-memory
  no-engine
  no-afalgeng
)

if [[ "$MODE" == "noasm" ]]; then
  CONF_FLAGS+=(no-asm)
fi

CC="$CC_BIN" ./Configure "${CONF_FLAGS[@]}"

# Avoid header-generation race: build all generated headers first,
# then compile libcrypto in parallel.
make -j1 build_generated
make -j"$JOBS" libcrypto.a

popd >/dev/null
