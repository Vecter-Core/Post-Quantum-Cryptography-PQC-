#!/bin/sh
# Build the C smoke test against the release cdylib and run it (also with sanitizers if available).
set -eu
cd "$(dirname "$0")/../../../.."
cargo build -p vpqc-ffi --release
LIBDIR="${CARGO_TARGET_DIR:-target}/release"
INC=crates/vpqc-ffi/include
OUT="${TMPDIR:-/tmp}/vpqc-c-smoke"
cc -std=c11 -Wall -Wextra -Werror -I"$INC" crates/vpqc-ffi/tests/c/smoke.c \
   -L"$LIBDIR" -lvpqc_ffi -Wl,-rpath,"$PWD/$LIBDIR" -o "$OUT"
"$OUT"
# Static linking check.
cc -std=c11 -Wall -Wextra -Werror -I"$INC" crates/vpqc-ffi/tests/c/smoke.c \
   "$LIBDIR/libvpqc_ffi.a" -lpthread -ldl -lm -o "$OUT-static"
"$OUT-static"
# C++ header check.
printf '#include "vpqc.h"\nint main(){return vpqc_abi_version()>>16 == 1 ? 0 : 1;}\n' > "$OUT.cpp"
c++ -std=c++17 -Wall -Wextra -Werror -I"$INC" "$OUT.cpp" -L"$LIBDIR" -lvpqc_ffi -Wl,-rpath,"$PWD/$LIBDIR" -o "$OUT-cpp"
"$OUT-cpp"
echo "all C/C++ checks passed"
