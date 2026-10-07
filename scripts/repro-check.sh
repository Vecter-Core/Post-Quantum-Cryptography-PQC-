#!/bin/bash
# Reproducibility check: build the CLI twice from two different directories and compare the
# binaries byte for byte. The build uses --locked, a fixed toolchain, path remapping (so the
# checkout directory and CARGO_HOME do not end up in the binary) and no incremental state.
#
# Usage: scripts/repro-check.sh [TARGET]    (default: the host target)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="${1:-$(rustc -vV | sed -n 's/^host: //p')}"
W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT
CH="${CARGO_HOME:-$HOME/.cargo}"
RH="${RUSTUP_HOME:-$HOME/.rustup}"

build() { # DIR
  mkdir -p "$1/src"
  (cd "$ROOT" && git archive HEAD) | tar -x -C "$1/src"
  (cd "$1/src" &&
    CARGO_INCREMENTAL=0 SOURCE_DATE_EPOCH=0 \
    RUSTFLAGS="--remap-path-prefix=$1/src=/src --remap-path-prefix=$CH=/cargo --remap-path-prefix=$RH=/rustup" \
    cargo build --release --locked --target "$TARGET" -p vpqc-cli --target-dir "$1/target" >/dev/null 2>&1)
  cp "$1/target/$TARGET/release/vpqc" "$1/vpqc"
}

build "$W/a"
build "$W/b"
A=$(sha256sum "$W/a/vpqc" | cut -d' ' -f1)
B=$(sha256sum "$W/b/vpqc" | cut -d' ' -f1)
echo "build A: $A"
echo "build B: $B"
if [ "$A" = "$B" ]; then
  echo "reproducible: identical binaries from different directories"
else
  echo "NOT reproducible" >&2
  cmp -l "$W/a/vpqc" "$W/b/vpqc" | head -5 >&2 || true
  exit 1
fi
