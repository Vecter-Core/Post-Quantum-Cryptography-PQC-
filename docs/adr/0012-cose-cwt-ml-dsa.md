# ADR-0012: COSE and CWT with pure ML-DSA

- Status: accepted
- Date: 2026-09-29

## Context
COSE (RFC 9052) is the binary counterpart of JOSE. It is used where JSON and base64 are too
heavy or where CBOR is already the format:
- IoT and CoAP (OSCORE / EDHOC ecosystems, ACE tokens);
- device attestation (EAT, RATS);
- firmware manifests (SUIT);
- ISO mDL / mdoc;
- WebAuthn / FIDO2 attestation.

Device identities and firmware signing keys are long-lived, and devices stay deployed for
10 to 20 years. That makes these signatures tier 1 in ADR-0003 once a verifier can be
updated.

draft-ietf-cose-dilithium defines ML-DSA for COSE, and IANA has registered its values:
- algorithms `ML-DSA-44/65/87` = -48 / -49 / -50;
- key type `AKP` = 7, with parameters `pub` = -1 and `priv` = -2 (the seed).

These are the same definitions `vpqc-jose` already implements for JOSE (ADR-0008). Google's
`coset` (the COSE library used by Android) ships these values.

## Decision
- New crate `vpqc-cose`, which provides:
  - COSE_Sign1 with the payload attached or detached, with external AAD;
  - `AKP` COSE_Keys (public, and private holding the 32-byte seed);
  - CWT (RFC 8392) encoding and validation;
  - CLI commands `vpqc cose key|sign|verify` and `vpqc cwt sign|verify`.

  Like JOSE, it uses pure ML-DSA-65/87 with an empty context over the `Sig_structure`, and no
  composite signatures, so that other COSE stacks can verify the results.
- The crate has its own small CBOR codec (about 300 lines) instead of a general CBOR library.
  This keeps the parser surface auditable and the decoding strict:
  - definite lengths only, with preferred (shortest) integer encodings;
  - no duplicate map keys, and map keys must be integers or strings;
  - UTF-8 text;
  - simple values limited to `false` / `true` / `null`;
  - depth at most 16 and no trailing bytes;
  - duplicate detection in linear time, and pre-allocation capped at 64 elements.

  Because of these rules, one value has exactly one encoding, so any accepted input without
  floats re-encodes byte for byte (a fuzz invariant). Our encoding is deterministic
  (RFC 8949 section 4.2.1), and public COSE_Keys are byte-identical to `coset`'s.
- Header rules:
  - Signing puts `alg`, `content type` and `kid` in the **protected** header, so they are
    signed.
  - Verification requires `alg` in the protected header and equal to the key's algorithm, so
    there is no algorithm substitution.
  - It rejects `crit` (nothing is implemented beyond the core parameters) and any label that
    appears in both header buckets (RFC 9052 section 3).
  - A `kid` in the unprotected header is reported as such (`kid_protected: false`).
- CWT validation mirrors `vpqc-jose`'s JWT rules:
  - `exp` is required by default, and `nbf` and the issuer are checked;
  - a token carrying `aud` is only accepted by a verifier that names its own audience;
  - text and array `aud` are both accepted;
  - integer and floating-point NumericDates are both accepted;
  - the CWT tag 61 is optional on input and not written.

## Consequences
- Interop is tested against an independent stack (`interop/cose.sh`, 60 checks), which uses
  `cbor2` for the COSE structures and OpenSSL through `cryptography` 50 for ML-DSA. The checks
  run in both directions:
  - OpenSSL verifies vpqc messages, including detached payloads, external AAD and CWTs;
  - vpqc verifies OpenSSL-signed messages and CWTs (tag 61, `aud` array, float `exp`);
  - vpqc rejects tampering, `alg` only in the unprotected header, `crit`, `kid` in both
    buckets, another algorithm or ML-DSA level, a wrong tag, another key and
    indefinite-length encoding;
  - keys move both ways.

  The Rust tests also cross-check against `coset`: identical keys, `coset`-built messages,
  `coset` verifying ours.
- A fuzz target covers CBOR, keys, messages and CWTs. It checks the "one encoding" invariant
  and that nothing verifies under a fixed key except what that key really signed. An injected
  bug that accepts non-preferred integers is found within a second.
- Sizes: an ML-DSA-65 COSE_Sign1 or CWT is about 3.35 KB, and a public COSE_Key is 1962 bytes
  (ML-DSA-87: 4.7 KB and 2602 bytes). That fits CoAP with block-wise transfer and BLE with
  fragmentation, but not single LoRaWAN or 802.15.4 frames. For those links the options are:
  - verify on a gateway;
  - keep an Ed25519 signature for the link, alongside ML-DSA for firmware and attestation;
  - wait for FN-DSA (smaller signatures).
- Not implemented: `COSE_Sign` (multiple signers), `COSE_Mac`/`COSE_Encrypt`, counter
  signatures, and composite ML-DSA for COSE (the draft is still changing).
