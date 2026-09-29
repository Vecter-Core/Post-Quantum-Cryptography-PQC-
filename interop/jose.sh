#!/bin/bash
# JOSE interop between the vpqc CLI and panva/jose on Node.js WebCrypto (OpenSSL ML-DSA).
# Requires: target/release/vpqc (or $VPQC), Node.js >= 24.7 as $NODE (default: node), npm.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VPQC="${VPQC:-$ROOT/target/release/vpqc}"
NODE="${NODE:-node}"
"$NODE" -e "crypto.subtle.generateKey({name:'ML-DSA-65'},false,['sign']).catch(()=>{console.error('Node.js with WebCrypto ML-DSA (>= 24.7) required');process.exit(3)})" 2>/dev/null
cd "$ROOT/interop/jose"
[ -d node_modules/jose ] || npm install --no-audit --no-fund --silent
"$NODE" --no-warnings interop.mjs "$VPQC"
