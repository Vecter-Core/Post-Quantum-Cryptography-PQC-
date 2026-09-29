#!/bin/bash
# SSH interop: `vpqc ssh probe` and `vpqc scan` against real OpenSSH servers (unprivileged, on
# loopback) with the default, a classical-only and a "remove the hybrids" KexAlgorithms.
# Checks, for every configuration:
#   * the probed KEXINIT list equals what `sshd -T` says the server will offer;
#   * --require-pq exits 0 exactly when a hybrid is offered, 2 otherwise;
#   * a real `ssh` client negotiates a hybrid exactly when the probe says one is offered;
#   * the scanner rates the same sshd_config consistently.
# Requires target/release/vpqc (or $VPQC), sshd (or $SSHD, absolute path), ssh, ssh-keygen, jq.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VPQC="${VPQC:-$ROOT/target/release/vpqc}"
SSHD="${SSHD:-$(command -v sshd || echo /usr/sbin/sshd)}"
W="$(mktemp -d)"
PIDS=()
cleanup() {
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  rm -rf "$W"
}
trap cleanup EXIT

pass=0
fail=0
check() { # description, command...
  local what="$1"
  shift
  if "$@"; then
    pass=$((pass + 1))
  else
    fail=$((fail + 1))
    echo "FAIL: $what" >&2
  fi
}

echo "$("$SSHD" -V 2>&1 | head -1)"
ssh-keygen -q -t ed25519 -N '' -f "$W/host"
has_mlkem=0
if ssh -Q kex | grep -qx mlkem768x25519-sha256; then has_mlkem=1; fi

# name | KexAlgorithms line ("" = defaults) | PQ expected (1/0)
configs=(
  "default||1"
  "classical|KexAlgorithms curve25519-sha256,ecdh-sha2-nistp256|0"
  "removed|KexAlgorithms -sntrup*,mlkem*|0"
  "appended|KexAlgorithms +diffie-hellman-group14-sha256|1"
  "sntrup-first|KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256|1"
)
if [ "$has_mlkem" = 1 ]; then
  configs+=("mlkem-only|KexAlgorithms mlkem768x25519-sha256|1")
fi

port=22220
for entry in "${configs[@]}"; do
  IFS='|' read -r name kexline want_pq <<<"$entry"
  port=$((port + 1))
  dir="$W/$name/etc/ssh"
  mkdir -p "$dir"
  conf="$dir/sshd_config"
  {
    echo "Port $port"
    echo "ListenAddress 127.0.0.1"
    echo "HostKey $W/host"
    echo "PidFile $W/$name.pid"
    echo "PasswordAuthentication no"
    echo "KbdInteractiveAuthentication no"
    if [ -n "$kexline" ]; then echo "$kexline"; fi
  } >"$conf"

  "$SSHD" -D -e -f "$conf" 2>"$W/$name.log" &
  PIDS+=($!)
  for _ in $(seq 50); do
    "$VPQC" ssh probe "127.0.0.1:$port" --timeout 1 >/dev/null 2>&1 && break
    sleep 0.1
  done

  # 1. The probe sees exactly the configured list (plus the protocol markers sshd appends).
  expected="$("$SSHD" -T -f "$conf" | awk '$1 == "kexalgorithms" { print $2 }')"
  json="$("$VPQC" ssh probe "127.0.0.1:$port" --json)"
  probed="$(jq -r '[.kex[] | select(.class != "Marker") | .name] | join(",")' <<<"$json")"
  check "$name: probe == sshd -T ($probed vs $expected)" [ "$probed" = "$expected" ]
  check "$name: strict KEX marker" [ "$(jq -r .strict_kex <<<"$json")" = true ]
  got_pq="$(jq -r 'if .post_quantum then 1 else 0 end' <<<"$json")"
  check "$name: post_quantum == $want_pq" [ "$got_pq" = "$want_pq" ]

  # 2. --require-pq exit status.
  set +e
  "$VPQC" ssh probe "127.0.0.1:$port" --require-pq >/dev/null
  code=$?
  set -e
  check "$name: --require-pq exit $code" [ "$code" = "$([ "$want_pq" = 1 ] && echo 0 || echo 2)" ]

  # 3. A real client negotiates a hybrid exactly when one is offered (authentication then
  # fails, which is expected: only the key exchange matters here).
  ssh -vv -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=5 -p "$port" nobody@127.0.0.1 true >"$W/$name.ssh" 2>&1 || true
  negotiated="$(awk '{ sub(/\r$/, "") } /kex: algorithm:/ && !n { print $NF; n = 1 }' "$W/$name.ssh")"
  class="$(jq -r --arg n "$negotiated" '.kex[] | select(.name == $n) | .class' <<<"$json")"
  case "$class" in HybridMlKem | HybridSntrup) neg_pq=1 ;; *) neg_pq=0 ;; esac
  [ -n "$negotiated" ] || neg_pq=none
  check "$name: client negotiated '$negotiated' ($class)" [ "$neg_pq" = "$want_pq" ]

  # 4. The scanner agrees on the configuration file.
  scan="$("$VPQC" scan --format json "$W/$name")"
  vulnerable="$(jq '[.findings[] | select(.algorithm == "SSH key exchange without post-quantum hybrid")] | length' <<<"$scan")"
  check "$name: scanner flags classical-only config ($vulnerable)" \
    [ "$vulnerable" = "$([ "$want_pq" = 1 ] && echo 0 || echo 1)" ]
  printf '  %-13s offered pq=%s negotiated=%s\n' "$name" "$got_pq" "$negotiated"
done

# 5. Nothing listening / not SSH: clean errors, never a hang.
set +e
"$VPQC" ssh probe 127.0.0.1:1 --timeout 2 >/dev/null 2>&1
check "closed port fails" [ $? -ne 0 ]
set -e

echo "ssh interop: $pass passed, $fail failed"
[ "$fail" = 0 ]
