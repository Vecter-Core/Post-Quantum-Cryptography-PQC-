#!/bin/sh
# Build the WebAssembly package into ./pkg (nodejs + web targets).
# Requires: rustup target add wasm32-unknown-unknown; cargo install wasm-bindgen-cli --version 0.2.129
set -eu
cd "$(dirname "$0")/.."
cargo build --target wasm32-unknown-unknown --release
WASM=target/wasm32-unknown-unknown/release/vpqc_wasm.wasm
rm -rf pkg && mkdir -p pkg
wasm-bindgen "$WASM" --target nodejs --out-dir pkg/node --out-name vpqc
wasm-bindgen "$WASM" --target web --out-dir pkg/web --out-name vpqc
# Optional size optimization when binaryen is installed.
if command -v wasm-opt >/dev/null 2>&1; then
  for f in pkg/node/vpqc_bg.wasm pkg/web/vpqc_bg.wasm; do wasm-opt -Oz "$f" -o "$f"; done
fi
rm -f pkg/*/.gitignore
echo "built: $(du -h pkg/node/vpqc_bg.wasm | cut -f1) wasm"
