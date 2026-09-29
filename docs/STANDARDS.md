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
| SSH hybrid KEX `mlkem768x25519-sha256`, `mlkem768nistp256-sha256`, `mlkem1024nistp384-sha384` | IETF SSHM draft (**check status**); OpenSSH >= 9.9, default in 10.0 | draft-ietf-sshm-mlkem-hybrid-kex | Classified as ML-KEM hybrid by `vpqc-ssh` (probe and config audit) |
| SSH `sntrup761x25519-sha512` | IETF SSHM draft (**check status**); OpenSSH default since 9.0 | draft-ietf-sshm-ntruprime-ssh | Accepted as hybrid, labelled "not NIST" |
| Composite signatures for X.509 | IETF LAMPS drafts | IETF datatracker | Align labels and OIDs when final |
| ML-DSA in X.509 (RFC 9881, was draft-ietf-lamps-dilithium-certificates) | RFC (**verify number**) | IETF | Implemented in `vpqc-x509`; interop-tested with OpenSSL (cryptography 50 / OpenSSL 4, Node.js / OpenSSL 3.5) |
| ML-KEM in X.509, ML-DSA / ML-KEM in CMS | IETF LAMPS | IETF datatracker | Align key encoding when final |
| IKEv2 multiple key exchanges (RFC 9370) and ML-KEM in IKEv2 | RFC 9370 (2023); ML-KEM for IKEv2: IETF IPSECME draft (**check status**); strongSwan >= 6.0 (`ke1_mlkem768`) | RFC 9370, draft-ietf-ipsecme-ikev2-mlkem | Audited by `vpqc scan` (ADR-0014) |
| WireGuard pre-shared key / Rosenpass | WireGuard protocol (Noise IKpsk2); Rosenpass (PQ AKE, formally analysed) | wireguard.com, rosenpass.eu | `vpqc wg psk-seal/psk-open` delivers PSKs over a hybrid sealed box; Rosenpass recommended for automatic rotation |
| Argon2id (RFC 9106) | RFC (2021) | RFC 9106 | Passphrase-protected secret keys (ADR-0013); defaults = RFC 9106 second recommended option; interop-tested with argon2-cffi |
| XChaCha20-Poly1305 | IETF CFRG draft (draft-irtf-cfrg-xchacha), widely deployed (libsodium) | IETF datatracker | Protected secret key encryption (ADR-0013); interop-tested with libsodium |
| ML-DSA for JOSE and COSE (`AKP` keys, `ML-DSA-65/87`) | IETF COSE WG draft (**check status**); IANA COSE values registered: ML-DSA-44/65/87 = -48/-49/-50, kty AKP = 7 (as shipped in `coset` 0.4) | draft-ietf-cose-dilithium | Implemented in `vpqc-jose` (JOSE; interop-tested with panva/jose) and `vpqc-cose` (COSE_Sign1, CWT; interop-tested with cbor2 + OpenSSL, cross-checked with `coset`) |
| Composite ML-DSA for JOSE/COSE | IETF draft, encoding still changing | IETF datatracker | Track; add when stable (ADR-0008) |
