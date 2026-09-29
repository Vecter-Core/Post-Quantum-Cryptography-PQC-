# Standards watch

Review quarterly. Verify against the primary source before changing behaviour.

| Item | Status when last checked (2026-09-29) | Source | Action for vpqc |
|---|---|---|---|
| FIPS 203 ML-KEM | Final (Aug 2024) | NIST CSRC | Implemented: ML-KEM-768/1024 |
| FIPS 204 ML-DSA | Final (Aug 2024) | NIST CSRC | Implemented: ML-DSA-65/87 |
| FIPS 205 SLH-DSA | Final (Aug 2024) | NIST CSRC | Planned (backend: RustCrypto `slh-dsa`, currently release candidate) |
| FIPS 206 FN-DSA | **Check status** | NIST CSRC | Planned after final |
| HQC | Selected as backup KEM (2025). **Check draft/final status** | NIST CSRC | Planned after FIPS |
| Additional signature on-ramp | In evaluation | NIST CSRC | Track only |
| NIST IR 8547 (transition) | Deprecate 112-bit classical by 2030, disallow by 2035 (**verify**) | NIST | Drives `standard` defaults |
| CNSA 2.0 | Timelines by system class (**verify**) | NSA | `cnsa2` profile |
| X-Wing KEM | CFRG draft, test vectors used in `vpqc-hybrid/tests` | draft-connolly-cfrg-xwing-kem | Implemented, KAT verified |
| TLS hybrid `X25519MLKEM768` | IETF TLS WG | IETF datatracker | Integration phase |
| Composite signatures for X.509 | IETF LAMPS drafts | IETF datatracker | Align labels and OIDs when final |
| ML-KEM / ML-DSA in X.509 and CMS | IETF LAMPS | IETF datatracker | Align key encoding when final |
| ML-DSA for JOSE and COSE (`AKP` keys, `ML-DSA-65/87`) | IETF COSE WG draft (**check status**) | draft-ietf-cose-dilithium | Implemented in `vpqc-jose` (JOSE); interop-tested with panva/jose. COSE not yet |
| Composite ML-DSA for JOSE/COSE | IETF draft, encoding still changing | IETF datatracker | Track; add when stable (ADR-0008) |
