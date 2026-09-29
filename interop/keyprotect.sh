#!/bin/bash
# Protected secret key interop: vpqc <-> argon2-cffi (reference Argon2) + PyNaCl (libsodium).
# Requires target/release/vpqc (or $VPQC) and $PYTHON with argon2-cffi and pynacl.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VPQC="${VPQC:-$ROOT/target/release/vpqc}"
PYTHON="${PYTHON:-python3}"
W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT
"$PYTHON" "$ROOT/interop/keyprotect/interop.py" "$VPQC" "$W"
