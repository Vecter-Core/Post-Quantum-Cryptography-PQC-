# ADR-0014: VPN: post-quantum WireGuard pre-shared keys, IPsec ML-KEM audit

- Status: accepted
- Date: 2026-09-29

## Context
VPN tunnels carry bulk traffic for years and are a classic "harvest now, decrypt later"
target, so they are tier 0 in ADR-0003.

**WireGuard** uses a fixed Noise IK handshake over X25519. It has no algorithm negotiation,
but it does accept an optional 32-byte **pre-shared key** per peer, which is mixed into the
handshake key derivation. If the PSK is unknown to the adversary, recorded traffic stays
confidential even when X25519 falls. An active attacker without the PSK also cannot complete
a handshake. Rosenpass builds on this: it runs a post-quantum AKE (Classic McEliece +
ML-KEM) beside WireGuard and rotates the PSK every two minutes.

**IPsec / IKEv2** gained multiple key exchanges in RFC 9370, and ML-KEM is being specified
for it. strongSwan 6.0 implements both, with proposals such as
`aes256gcm16-prfsha384-x25519-ke1_mlkem768`.

In practice, most WireGuard deployments have no PSK, and most IPsec proposals are classical.

## Decision
- **No new VPN protocol.** ADR-0002 applies: vpqc uses the mechanisms these VPNs already have.
- **`vpqc wg psk-seal` / `psk-open`.** A random 32-byte PSK is delivered to the peer in a
  vpqc sealed box (X-Wing hybrid, ADR-0005), an existing construction.
  - The associated data is `"vpqc/wireguard-psk/v1" || min(pkA, pkB) || max(pkA, pkB)`,
    where `pkA` and `pkB` are the two WireGuard public keys. A sealed PSK only opens for that
    tunnel.
  - Output files are WireGuard base64, mode 0600, ready for
    `wg set IFACE peer KEY preshared-key FILE`.
- **Sender authentication.** A sealed box does not say who sealed it, and anyone can seal a
  PSK of their choosing to Bob's public key. An attacker on the delivery channel who swaps in
  their own PSK knows it, and the tunnel falls back to X25519 alone.
  - `--sign-key` signs `aad || sealed` with the sender's vpqc signing key (hybrid Ed25519 +
    ML-DSA-65 by default), with the context `vpqc/wireguard-psk/v1`.
  - `psk-open --from` requires that signature.
  - Signed format: `"VPQCWGS1" len:u32 | sealed | signature`.
  - Use `--sign-key`/`--from` unless the delivery channel is already authenticated (SSH,
    configuration management).
- **`vpqc scan` audits VPN configurations:**
  - WireGuard in three syntaxes: wg-quick, systemd-networkd `.netdev` (`[WireGuardPeer]`,
    `PresharedKeyFile`) and NetworkManager keyfiles (`[wireguard-peer.*]`). A peer without a
    PSK is T0. A peer with one is reported with the caveat that it helps only if the PSK was
    delivered over a post-quantum or out-of-band channel.
  - strongSwan `swanctl.conf` / `ipsec.conf` proposals:
    - classical groups only is T0;
    - a mixed list is flagged, because a peer may pick the classical proposal;
    - ML-KEM together with a classical group is reported as hybrid (RFC 9370);
    - `default`, and ESP without PFS, are skipped.
  - Key lines (`PrivateKey`, `PresharedKey`...) are blanked before the generic text rules
    run, and key material never reaches a report.

## Consequences
- `interop/wireguard.sh` runs **real WireGuard peers** on loopback. It uses kernel WireGuard
  where available and `wireguard-go` otherwise, and runs as root in CI. It checks (19 checks):
  - the handshake completes with the vpqc-delivered PSK;
  - a mismatched PSK blocks the handshake;
  - a sealed PSK opens for neither another tunnel nor another key;
  - signed delivery rejects a PSK signed by someone else, an unsigned PSK when `--from` is
    required, and a tampered signature, writing no PSK file;
  - rotation works;
  - the scanner rates the live `wg showconf`, and no key material appears in its report.
- Limits of a static PSK compared with Rosenpass:
  - The PSK protects traffic until it is rotated. If a peer's vpqc secret key is later
    compromised, recorded sealed PSKs open, so the PSK itself has no forward secrecy.
    Rotate regularly (a timer running `psk-seal`/`psk-open`), and protect the vpqc secret
    key (ADR-0013).
  - For high-value links that can run an extra daemon, Rosenpass is preferable: it rotates
    automatically with a post-quantum AKE.
  - `vpqc wg` targets fleets that cannot run that daemon, and one-off hardening.
- IPsec is audited, not configured: the fix is a strongSwan 6 proposal change. OpenVPN and
  other TLS-based VPNs are covered by the TLS guidance (`X25519MLKEM768` groups) and the
  generic scanner rules.
