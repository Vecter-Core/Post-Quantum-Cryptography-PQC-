#!/bin/bash
# Cross-language interoperability suite.
#
# For every profile and every combination of (key generator, sealer, opener) and
# (key generator, signer, verifier) across the Rust CLI, Python, Node.js (WASM) and Go,
# data produced by one implementation must be accepted by all others, and tampered
# data / wrong contexts must be rejected by all.
#
# Environment: VPQC_CLI (Rust CLI), PYTHON (interpreter with vpqc installed), NODE, GO_DRIVER.
# Set INTEROP_PHP=1 / INTEROP_RUBY=1 (needs the ffi gem) to include PHP / Ruby.
# Set INTEROP_JAVA=1 to include Java (needs `mvn package -DskipTests` in bindings/java first;
# slower because every call starts a JVM).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VPQC_CLI="${VPQC_CLI:-$ROOT/target/release/vpqc}"
PYTHON="${PYTHON:-python3}"
NODE="${NODE:-node}"
GO_DRIVER="${GO_DRIVER:-$ROOT/target/interop-go}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Each implementation is a command prefix; all speak the same protocol as the CLI wrappers below.
cli() { # cli keygen|seal|open|sign|verify ...
  local c="$1"; shift
  case "$c" in
    keygen) "$VPQC_CLI" keygen --purpose "$1" --profile "$2" --out "$3" --force 2>/dev/null
            mv "$3.vpqc-secret" "$3.sec" ;;
    seal)   "$VPQC_CLI" seal --to "$1" --aad "$2" -o "$4" "$3" ;;
    open)   "$VPQC_CLI" open --key "$1" --aad "$2" -o "$4" "$3" ;;
    sign)   "$VPQC_CLI" sign --key "$1" --context "$2" -o "$4" "$3" ;;
    verify) "$VPQC_CLI" verify --key "$1" --context "$2" --sig "$3" "$4" 2>/dev/null ;;
    encrypt-file) "$VPQC_CLI" encrypt --to "$1" --aad "$2" -o "$4" --force "$3" ;;
    encrypt-file-multi) local aad="$1" in="$2" out="$3"; shift 3
            local to=(); for k in "$@"; do to+=(--to "$k"); done
            "$VPQC_CLI" encrypt "${to[@]}" --aad "$aad" -o "$out" --force "$in" ;;
    rewrap-file) local sec="$1" aad="$2" in="$3" out="$4"; shift 4
            local to=(); for k in "$@"; do to+=(--to "$k"); done
            "$VPQC_CLI" rewrap --key "$sec" "${to[@]}" --aad "$aad" -o "$out" --force "$in" ;;
    decrypt-file) "$VPQC_CLI" decrypt --key "$1" --aad "$2" -o "$4" --force "$3" ;;
    protect) VPQC_PASSPHRASE="$2" VPQC_PASSPHRASE_FILE= "$VPQC_CLI" protect "$1" --passphrase --kdf-memory 8 -o "$3" --force 2>/dev/null ;;
    unprotect) VPQC_PASSPHRASE="$2" VPQC_PASSPHRASE_FILE= "$VPQC_CLI" unprotect "$1" -o "$3" --force ;;
  esac
}
py()   { "$PYTHON" "$ROOT/interop/drivers/py_driver.py" "$@"; }
node_() { "$NODE" "$ROOT/interop/drivers/node_driver.js" "$@"; }
go_() { # go driver takes numeric profile ids
  if [ "$1" = keygen ]; then
    local id; case "$3" in standard) id=1;; fast-auth) id=2;; cnsa2) id=3;; high) id=4;; esac
    "$GO_DRIVER" keygen "$2" "$id" "$4"
  else "$GO_DRIVER" "$@"; fi
}
JAVA_OUT=""
java_() {
  # UTF-8 locale: under the C locale the JVM decodes non-ASCII arguments (the passphrases
  # below) to U+FFFD.
  LC_ALL=C.UTF-8 "${JAVA:-java}" --enable-preview --enable-native-access=ALL-UNNAMED -XX:TieredStopAtLevel=1 -Xshare:auto \
    -Dvpqc.library.path="$ROOT/target/release" -cp "$JAVA_OUT:$ROOT/bindings/java/target/classes" JavaDriver "$@" 2> >(grep -v JAVA_TOOL_OPTIONS >&2)
}
php_()  { VPQC_LIBRARY="$ROOT/target/release/libvpqc_ffi.so" "${PHP:-php}" -d ffi.enable=1 "$ROOT/interop/drivers/php_driver.php" "$@"; }
ruby_() { VPQC_LIBRARY="$ROOT/target/release/libvpqc_ffi.so" "${RUBY:-ruby}" "$ROOT/interop/drivers/ruby_driver.rb" "$@"; }
run() { # run IMPL CMD ARGS...
  local impl="$1"; shift
  case "$impl" in cli) cli "$@";; py) py "$@";; node) node_ "$@";; go) go_ "$@";; java) java_ "$@";; php) php_ "$@";; ruby) ruby_ "$@";; esac
}

IMPLS=(cli py node go)
[ "${INTEROP_PHP:-0}" = 1 ] && IMPLS+=(php)
[ "${INTEROP_RUBY:-0}" = 1 ] && IMPLS+=(ruby)
if [ "${INTEROP_JAVA:-0}" = 1 ]; then
  JAVA_OUT="$WORK/java-driver"
  mkdir -p "$JAVA_OUT"
  "${JAVAC:-javac}" --enable-preview --release "${JAVA_RELEASE:-21}" -cp "$ROOT/bindings/java/target/classes" \
    -d "$JAVA_OUT" "$ROOT/interop/drivers/JavaDriver.java" 2>&1 | grep -v -e JAVA_TOOL_OPTIONS -e "^Note:" || true
  IMPLS+=(java)
fi
PROFILES=(standard fast-auth cnsa2 high)
fail=0; total=0
expect_ok()   { total=$((total+1)); if ! "$@" 2>"$WORK/err"; then echo "FAIL (expected success): $*"; cat "$WORK/err"; fail=$((fail+1)); fi; }
expect_fail() { total=$((total+1)); if "$@" 2>/dev/null; then echo "FAIL (expected rejection): $*"; fail=$((fail+1)); fi; }

head -c 3000 /dev/urandom > "$WORK/msg.bin"
for profile in "${PROFILES[@]}"; do
  for g in "${IMPLS[@]}"; do
    run "$g" keygen encrypt "$profile" "$WORK/enc-$g"
    run "$g" keygen sign "$profile" "$WORK/sig-$g"
    for s in "${IMPLS[@]}"; do
      # Encryption: key from g, sealed by s, opened by every implementation.
      run "$s" seal "$WORK/enc-$g.pub" "ctx-1" "$WORK/msg.bin" "$WORK/sealed"
      for o in "${IMPLS[@]}"; do
        rm -f "$WORK/plain"
        expect_ok run "$o" open "$WORK/enc-$g.sec" "ctx-1" "$WORK/sealed" "$WORK/plain"
        cmp -s "$WORK/plain" "$WORK/msg.bin" || { echo "FAIL: plaintext differs ($g,$s,$o,$profile)"; fail=$((fail+1)); }
        expect_fail run "$o" open "$WORK/enc-$g.sec" "wrong-ctx" "$WORK/sealed" "$WORK/plain2"
      done
      # Signatures: key from g, signed by s, verified by every implementation.
      run "$s" sign "$WORK/sig-$g.sec" "app/v1" "$WORK/msg.bin" "$WORK/signature"
      for o in "${IMPLS[@]}"; do
        expect_ok   run "$o" verify "$WORK/sig-$g.pub" "app/v1" "$WORK/signature" "$WORK/msg.bin"
        expect_fail run "$o" verify "$WORK/sig-$g.pub" "app/v2" "$WORK/signature" "$WORK/msg.bin"
      done
    done
  done
  echo "profile $profile: done"
done

# Streaming file encryption (ADR-0007): every implementation encrypts, every one decrypts
# (Node uses the incremental StreamEncryptor/StreamDecryptor classes of the WASM build).
STREAM_IMPLS=("${IMPLS[@]}")
head -c 300000 /dev/urandom > "$WORK/big.bin"   # several 64 KiB chunks
for profile in standard high; do
  run cli keygen encrypt "$profile" "$WORK/senc"
  for e in "${STREAM_IMPLS[@]}"; do
    rm -f "$WORK/big.vpqc"
    run "$e" encrypt-file "$WORK/senc.pub" "backup" "$WORK/big.bin" "$WORK/big.vpqc"
    for d in "${STREAM_IMPLS[@]}"; do
      rm -f "$WORK/big.out"
      expect_ok run "$d" decrypt-file "$WORK/senc.sec" "backup" "$WORK/big.vpqc" "$WORK/big.out"
      cmp -s "$WORK/big.out" "$WORK/big.bin" || { echo "FAIL: stream plaintext differs ($e -> $d, $profile)"; fail=$((fail+1)); }
      rm -f "$WORK/big.bad"
      expect_fail run "$d" decrypt-file "$WORK/senc.sec" "wrong" "$WORK/big.vpqc" "$WORK/big.bad"
      [ -e "$WORK/big.bad" ] && { echo "FAIL: $d left output after failed decryption"; fail=$((fail+1)); }
    done
  done
done
# Truncated stream is rejected by every implementation.
head -c 200000 "$WORK/big.vpqc" > "$WORK/cut.vpqc"
for d in "${STREAM_IMPLS[@]}"; do
  expect_fail run "$d" decrypt-file "$WORK/senc.sec" "backup" "$WORK/cut.vpqc" "$WORK/cut.out"
done
# The committed regression vector decrypts identically everywhere.
"$PYTHON" - "$ROOT/crates/vpqc/tests/data/stream-v1.json" "$WORK" <<'PY'
import json, sys, subprocess
v = json.load(open(sys.argv[1])); w = sys.argv[2]
open(f"{w}/vec.vpqc", "wb").write(bytes.fromhex(v["ciphertext"]))
open(f"{w}/vec.pt", "wb").write(bytes((i * 31) % 251 for i in range(v["plaintext_len"])))
open(f"{w}/vec.aad", "w").write(bytes.fromhex(v["aad"]).decode())
sk = bytes.fromhex(v["secret_key"])
import base64
b64 = base64.b64encode(sk).decode()
open(f"{w}/vec.sec", "w").write("-----BEGIN VPQC SECRET KEY-----\n" + "\n".join(b64[i:i+64] for i in range(0, len(b64), 64)) + "\n-----END VPQC SECRET KEY-----\n")
PY
for d in "${STREAM_IMPLS[@]}"; do
  rm -f "$WORK/vec.out"
  expect_ok run "$d" decrypt-file "$WORK/vec.sec" "$(cat "$WORK/vec.aad")" "$WORK/vec.vpqc" "$WORK/vec.out"
  cmp -s "$WORK/vec.out" "$WORK/vec.pt" || { echo "FAIL: $d regression vector plaintext differs"; fail=$((fail+1)); }
done
echo "streaming: done"

# Multi-recipient streams (ADR-0009): every implementation encrypts to three recipients of
# different profiles; every implementation decrypts with each recipient key and rejects an
# outsider. Then every implementation re-wraps (drops two recipients, adds the outsider)
# without re-encrypting, and every implementation checks the new recipient list.
for p in standard high cnsa2; do run cli keygen encrypt "$p" "$WORK/mr-$p"; done
run cli keygen encrypt standard "$WORK/mr-out"
for e in "${STREAM_IMPLS[@]}"; do
  rm -f "$WORK/mr.vpqc"
  expect_ok run "$e" encrypt-file-multi "team" "$WORK/big.bin" "$WORK/mr.vpqc" \
    "$WORK/mr-standard.pub" "$WORK/mr-high.pub" "$WORK/mr-cnsa2.pub"
  for d in "${STREAM_IMPLS[@]}"; do
    for p in standard high cnsa2; do
      rm -f "$WORK/mr.out"
      expect_ok run "$d" decrypt-file "$WORK/mr-$p.sec" "team" "$WORK/mr.vpqc" "$WORK/mr.out"
      cmp -s "$WORK/mr.out" "$WORK/big.bin" || { echo "FAIL: multi-recipient plaintext differs ($e -> $d, $p)"; fail=$((fail+1)); }
    done
    expect_fail run "$d" decrypt-file "$WORK/mr-out.sec" "team" "$WORK/mr.vpqc" "$WORK/mr.bad"
  done
done
for r in "${STREAM_IMPLS[@]}"; do
  rm -f "$WORK/mr-re.vpqc"
  expect_ok run "$r" rewrap-file "$WORK/mr-high.sec" "team" "$WORK/mr.vpqc" "$WORK/mr-re.vpqc" \
    "$WORK/mr-cnsa2.pub" "$WORK/mr-out.pub"
  for d in "${STREAM_IMPLS[@]}"; do
    rm -f "$WORK/mr.out"
    expect_ok run "$d" decrypt-file "$WORK/mr-out.sec" "team" "$WORK/mr-re.vpqc" "$WORK/mr.out"
    cmp -s "$WORK/mr.out" "$WORK/big.bin" || { echo "FAIL: re-wrapped plaintext differs ($r -> $d)"; fail=$((fail+1)); }
    expect_fail run "$d" decrypt-file "$WORK/mr-standard.sec" "team" "$WORK/mr-re.vpqc" "$WORK/mr.bad"
  done
done
"$PYTHON" - "$ROOT/crates/vpqc/tests/data/multistream-v1.json" "$WORK" <<'PY'
import json, sys, base64
v = json.load(open(sys.argv[1])); w = sys.argv[2]
open(f"{w}/mvec.vpqc", "wb").write(bytes.fromhex(v["ciphertext"]))
open(f"{w}/mvec.pt", "wb").write(bytes((i * 31) % 251 for i in range(v["plaintext_len"])))
for i, sk in enumerate(v["secret_keys"]):
    b64 = base64.b64encode(bytes.fromhex(sk)).decode()
    open(f"{w}/mvec{i}.sec", "w").write("-----BEGIN VPQC SECRET KEY-----\n" + "\n".join(b64[j:j+64] for j in range(0, len(b64), 64)) + "\n-----END VPQC SECRET KEY-----\n")
PY
for d in "${STREAM_IMPLS[@]}"; do
  for i in 0 1; do
    rm -f "$WORK/mvec.out"
    expect_ok run "$d" decrypt-file "$WORK/mvec$i.sec" "vector" "$WORK/mvec.vpqc" "$WORK/mvec.out"
    cmp -s "$WORK/mvec.out" "$WORK/mvec.pt" || { echo "FAIL: $d multi-recipient vector differs"; fail=$((fail+1)); }
  done
done
echo "multi-recipient streaming: done"

# Passphrase-protected secret keys (ADR-0013): every implementation protects a key, every
# implementation recovers exactly the original key and rejects a wrong passphrase.
for p in standard high; do
  run cli keygen encrypt "$p" "$WORK/pk-$p"
  for w in "${IMPLS[@]}"; do
    rm -f "$WORK/pk.prot"
    expect_ok run "$w" protect "$WORK/pk-$p.sec" "mật khẩu $p" "$WORK/pk.prot"
    for r in "${IMPLS[@]}"; do
      rm -f "$WORK/pk.plain"
      expect_ok run "$r" unprotect "$WORK/pk.prot" "mật khẩu $p" "$WORK/pk.plain"
      cmp -s "$WORK/pk.plain" "$WORK/pk-$p.sec" || { echo "FAIL: protected key differs ($w -> $r, $p)"; fail=$((fail+1)); }
      expect_fail run "$r" unprotect "$WORK/pk.prot" "wrong" "$WORK/pk.bad"
    done
  done
done
echo "protected secret keys: done"

# Tampered data is rejected everywhere.
cp "$WORK/signature" "$WORK/bad.sig"; printf '\x00' | dd of="$WORK/bad.sig" bs=1 seek=100 conv=notrunc 2>/dev/null
cp "$WORK/msg.bin" "$WORK/bad.msg"; printf '\x01' | dd of="$WORK/bad.msg" bs=1 seek=5 conv=notrunc 2>/dev/null
for o in "${IMPLS[@]}"; do
  expect_fail run "$o" verify "$WORK/sig-$o.pub" "app/v1" "$WORK/bad.sig" "$WORK/msg.bin"
  expect_fail run "$o" verify "$WORK/sig-cli.pub" "app/v1" "$WORK/signature" "$WORK/bad.msg"
done

echo "interop checks: $total, failures: $fail"
[ "$fail" -eq 0 ]
