# ADR-0005: Versioned envelopes with downgrade protection

- Status: accepted
- Date: 2026-09-29

## Decision
Every serialized object starts with `VPQC`, a version byte and an object kind (see
`vpqc-format`). For sealed boxes the header and the KEM ciphertext are

1. hashed into the key derivation (`SHAKE256("vpqc-seal-v1" || len || header || ss)`), and
2. authenticated as AEAD associated data,

so changing an algorithm identifier or the KEM ciphertext makes decryption fail.
For signatures, the **verifier's key** decides the algorithm; a signature that names a
different algorithm is rejected. Composite signatures sign a domain-separated representative
`M'` that includes the algorithm id and the caller's context, so a half of a composite cannot
be replayed as a standalone signature (tests: `algorithm_relabelling_is_rejected`).

## Consequences
- Formats are stable per version; a new version byte is required for any change.
- Composite signature labels are vpqc-specific until the IETF LAMPS composite RFC is final.
  Interop with the RFC is a tracked work item.
