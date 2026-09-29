#!/bin/bash
# COSE/CWT interop between the vpqc CLI and an independent implementation: Python cbor2 for the
# COSE structures, OpenSSL (through `cryptography` >= 50) for ML-DSA.
# Requires target/release/vpqc (or $VPQC) and $PYTHON with cryptography >= 50 and cbor2.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VPQC="${VPQC:-$ROOT/target/release/vpqc}"
PYTHON="${PYTHON:-python3}"
W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT
"$PYTHON" "$ROOT/interop/cose/interop.py" "$VPQC" "$W"
