# ADR-0004: Secret keys are stored as seeds

- Status: accepted
- Date: 2026-09-29

## Decision
Every vpqc secret key is a compact seed: 32 bytes (X-Wing, ML-DSA, composite, Ed25519) or
64 bytes (ML-KEM, `d || z`). The expanded key is derived on each operation and dropped.

## Rationale
- FIPS 203/204 allow seed storage, and X-Wing mandates a 32-byte seed as its private key.
- Small, fixed-size secrets are easy to store, zeroize and back up.
- The expanded ML-KEM decapsulation key must never be exchanged between implementations
  (X-Wing draft, "Keeping expanded decapsulation key around"): binding properties do not hold.

## Consequences
- Each decapsulation or signature repeats key expansion (tens of microseconds for ML-KEM).
  A cached "expanded key" handle is a planned optimization behind an opaque type.
- libcrux types holding expanded keys are not zeroized by libcrux; we zeroize what we own.
