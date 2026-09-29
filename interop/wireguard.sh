#!/bin/bash
# WireGuard interop (ADR-0014): real WireGuard peers on loopback with a pre-shared key that
# `vpqc wg psk-seal` draws and seals to the peer's vpqc key and `vpqc wg psk-open` recovers.
# Checks that:
#   * both sides recover the same PSK, in a format `wg` accepts;
#   * the tunnel completes a handshake with it, and does not with a mismatched PSK;
#   * a sealed PSK cannot be opened for another tunnel (other WireGuard keys) or another key;
#   * rotation (seal again, open again) gives a new PSK and a working tunnel;
#   * `vpqc scan` rates peers with and without a PSK.
# Needs root (CAP_NET_ADMIN), wg, ip, and kernel WireGuard or wireguard-go with /dev/net/tun.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VPQC="${VPQC:-$ROOT/target/release/vpqc}"
W="$(mktemp -d)"
IF_A=vpqcwga IF_B=vpqcwgb
cleanup() {
  ip link del "$IF_A" 2>/dev/null || true
  ip link del "$IF_B" 2>/dev/null || true
  rm -rf "$W"
}
trap cleanup EXIT
umask 077
cd "$W"

pass=0 fail=0
check() { # description, command...
  local what="$1"
  shift
  if "$@"; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "FAIL: $what" >&2; fi
}

mkif() {
  if ip link add dev "$1" type wireguard 2>/dev/null; then
    echo "  $1: kernel WireGuard"
  else
    wireguard-go "$1" >/dev/null 2>&1
    echo "  $1: wireguard-go"
  fi
}

# Keys: WireGuard for the tunnel, vpqc (hybrid X-Wing) for delivering the PSK to B.
for s in a b c; do wg genkey > "$s.key"; wg pubkey < "$s.key" > "$s.pub"; done
"$VPQC" keygen --purpose encrypt --out bob >/dev/null 2>&1
"$VPQC" keygen --purpose encrypt --out eve >/dev/null 2>&1

# A seals, B opens.
"$VPQC" wg psk-seal --to bob.pub --wg-local "$(cat a.pub)" --wg-peer "$(cat b.pub)" --psk-out a.psk -o sealed
"$VPQC" wg psk-open --key bob.vpqc-secret --wg-local "$(cat b.pub)" --wg-peer "$(cat a.pub)" -o b.psk sealed
check "both sides hold the same PSK" cmp -s a.psk b.psk
check "wg accepts the PSK format" sh -c 'wg pubkey < b.psk >/dev/null'
check "PSK file is private" [ "$(stat -c %a a.psk)" = 600 ]
check "another tunnel cannot open it" \
  bash -c "! '$VPQC' wg psk-open --key bob.vpqc-secret --wg-local '$(cat b.pub)' --wg-peer '$(cat c.pub)' -o x.psk sealed 2>/dev/null"
check "another vpqc key cannot open it" \
  bash -c "! '$VPQC' wg psk-open --key eve.vpqc-secret --wg-local '$(cat b.pub)' --wg-peer '$(cat a.pub)' -o y.psk sealed 2>/dev/null"

# Sender authentication: a sealed box does not say who sealed it, so Eve can seal a PSK of
# her choosing to Bob. Signed by Alice and checked with --from, only Alice's PSK is accepted.
"$VPQC" keygen --purpose sign --out alice >/dev/null 2>&1
"$VPQC" keygen --purpose sign --out mallory >/dev/null 2>&1
"$VPQC" wg psk-seal --to bob.pub --wg-local "$(cat a.pub)" --wg-peer "$(cat b.pub)" --psk-out s.psk \
  --sign-key alice.vpqc-secret -o signed
"$VPQC" wg psk-open --key bob.vpqc-secret --from alice.pub --wg-local "$(cat b.pub)" --wg-peer "$(cat a.pub)" -o s2.psk signed
check "signed PSK verified and opened" cmp -s s.psk s2.psk
"$VPQC" wg psk-seal --to bob.pub --wg-local "$(cat a.pub)" --wg-peer "$(cat b.pub)" --psk-out e.psk \
  --sign-key mallory.vpqc-secret -o forged
check "PSK signed by someone else is rejected" \
  bash -c "! '$VPQC' wg psk-open --key bob.vpqc-secret --from alice.pub --wg-local '$(cat b.pub)' --wg-peer '$(cat a.pub)' -o f.psk forged 2>/dev/null"
check "unsigned PSK is rejected when --from is required" \
  bash -c "! '$VPQC' wg psk-open --key bob.vpqc-secret --from alice.pub --wg-local '$(cat b.pub)' --wg-peer '$(cat a.pub)' -o g.psk sealed 2>/dev/null"
check "signed PSK needs --from" \
  bash -c "! '$VPQC' wg psk-open --key bob.vpqc-secret --wg-local '$(cat b.pub)' --wg-peer '$(cat a.pub)' -o h.psk signed 2>/dev/null"
python3 - signed <<'PY'
import sys; b = bytearray(open(sys.argv[1], "rb").read()); b[-10] ^= 1; open("signed.bad", "wb").write(b)
PY
check "tampered signature is rejected" \
  bash -c "! '$VPQC' wg psk-open --key bob.vpqc-secret --from alice.pub --wg-local '$(cat b.pub)' --wg-peer '$(cat a.pub)' -o i.psk signed.bad 2>/dev/null"
check "no PSK file written on rejection" bash -c "[ ! -e f.psk ] && [ ! -e g.psk ] && [ ! -e h.psk ] && [ ! -e i.psk ]"

echo "interfaces:"
mkif "$IF_A"
mkif "$IF_B"
wg set "$IF_A" private-key a.key listen-port 51820
wg set "$IF_B" private-key b.key listen-port 51821
ip link set "$IF_A" up
ip link set "$IF_B" up
ip addr add 10.99.0.1/32 dev "$IF_A"
ip route add 10.99.1.0/24 dev "$IF_A"

peers() { # PSK_A PSK_B: (re)configure both peers, dropping any session
  wg set "$IF_A" peer "$(cat b.pub)" remove 2>/dev/null || true
  wg set "$IF_B" peer "$(cat a.pub)" remove 2>/dev/null || true
  wg set "$IF_A" peer "$(cat b.pub)" preshared-key "$1" endpoint 127.0.0.1:51821 allowed-ips 10.99.1.0/24
  wg set "$IF_B" peer "$(cat a.pub)" preshared-key "$2" endpoint 127.0.0.1:51820 allowed-ips 10.99.0.0/24
}
handshake() { # true if both sides complete a handshake within ~6 s
  for _ in 1 2 3 4 5 6; do
    python3 -c "import socket; socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b'x', ('10.99.1.5', 9))"
    sleep 1
    local ta tb
    ta=$(wg show "$IF_A" latest-handshakes | awk '{print $2}')
    tb=$(wg show "$IF_B" latest-handshakes | awk '{print $2}')
    if [ "${ta:-0}" != 0 ] && [ "${tb:-0}" != 0 ]; then return 0; fi
  done
  return 1
}

peers a.psk b.psk
check "handshake with the vpqc PSK" handshake
wg genpsk > wrong.psk
peers a.psk wrong.psk
if handshake; then fail=$((fail + 1)); echo "FAIL: mismatched PSK completed a handshake" >&2; else pass=$((pass + 1)); fi

# Rotation: new PSK sealed and opened again.
cp a.psk old.psk
"$VPQC" wg psk-seal --to bob.pub --wg-local "$(cat a.pub)" --wg-peer "$(cat b.pub)" --psk-out a.psk --base64 --force > sealed.txt
"$VPQC" wg psk-open --key bob.vpqc-secret --wg-local "$(cat b.pub)" --wg-peer "$(cat a.pub)" -o b.psk --force sealed.txt
check "rotation gives a new PSK" bash -c "! cmp -s a.psk old.psk"
check "rotated PSK matches on both sides" cmp -s a.psk b.psk
peers a.psk b.psk
check "handshake after rotation" handshake

# Scanner: the running configuration, with and without a PSK.
wg showconf "$IF_A" > with-psk.conf
sed '/PresharedKey/d' with-psk.conf > no-psk.conf
check "scan: peer with PSK" bash -c "'$VPQC' scan --format json with-psk.conf | grep -q 'WireGuard peer with pre-shared key'"
check "scan: peer without PSK is T0" bash -c "'$VPQC' scan --format json no-psk.conf | grep -q 'WireGuard peer without pre-shared key'"
check "scan: no key material in the report" bash -c "! '$VPQC' scan --all with-psk.conf | grep -qF '$(cat a.psk)'"

echo "wireguard interop: $pass passed, $fail failed"
[ "$fail" = 0 ]
