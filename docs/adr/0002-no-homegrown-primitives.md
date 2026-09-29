# ADR-0002: Do not implement primitives ourselves

- Status: accepted
- Date: 2026-09-29

## Context
ML-KEM and ML-DSA are subtle to implement securely (constant time, side channels,
implicit rejection, rejection sampling). Independent, verified implementations exist.

## Decision
Primitives come from audited or formally verified backends behind the `Kem` and
`SignatureScheme` traits. The default backend is **libcrux** (verified). The project owns
the *constructions on top*: hybrid combiners, composite signatures, envelopes, policy.

Every backend operation used by vpqc is cross-checked against an independent
implementation (RustCrypto `ml-kem`, `ml-dsa`) in `crates/vpqc-backend-libcrux/tests/`.
The hybrid KEM is checked against the official X-Wing test vectors.

## Consequences
- Bugs in a backend are caught by differential tests before release.
- Backends can be swapped (for example `aws-lc-rs` for a FIPS 140-3 boundary) without API changes.
- We depend on upstream release cadence; versions are pinned in `Cargo.lock`.
