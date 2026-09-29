#!/bin/bash
# X.509 interop between the vpqc CLI and OpenSSL: Python `cryptography` (with ML-DSA) and
# Node.js >= 24.7. Requires target/release/vpqc (or $VPQC), $PYTHON with cryptography >= 50,
# $NODE.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VPQC="${VPQC:-$ROOT/target/release/vpqc}"
PYTHON="${PYTHON:-python3}"
NODE="${NODE:-node}"
W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT
"$PYTHON" "$ROOT/interop/x509/interop.py" "$VPQC" "$NODE" "$W"
