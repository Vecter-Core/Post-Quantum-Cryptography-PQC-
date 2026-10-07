# Changelog

All notable changes. The project is pre-release (`0.0.x`) and unaudited: formats and APIs may
still change, and nothing here is yet suitable for protecting real secrets.

## Unreleased

### Added
- **Core:** hybrid and post-quantum key encapsulation and signatures behind profiles
  (`standard`, `fast-auth`, `cnsa2`, `high`); wire formats with algorithm identifiers inside
  the authenticated data; streaming encryption for files of any size (ADR-0007); multi-recipient
  envelopes with re-wrapping for key rotation (ADR-0009); HPKE with hybrid KEMs; TLS 1.3
  `X25519MLKEM768` sidecar.
- **Standards interop:** JOSE/JWT (ADR-0008) and COSE/CWT (ADR-0012) with ML-DSA; X.509 with
  ML-DSA, RFC 9881 (ADR-0010); SSH probe and `KexAlgorithms` audit (ADR-0011); WireGuard
  pre-shared keys and WireGuard/IPsec audit (ADR-0014).
- **Key protection:** secret keys at rest under a passphrase (Argon2id) or a KMS/TPM-wrapped key
  (ADR-0013); in every language binding for passphrases.
- **Migration tooling:** `vpqc scan` with tiering (ADR-0003), CycloneDX 1.6 CBOM and SARIF 2.1.0
  output, VPN/SSH configuration audits.
- **Bindings:** Rust, C (ABI 1.1), Python, JavaScript/WebAssembly, Go, Java (+ JCA provider), PHP,
  Ruby, .NET. Cross-language interop matrix over every implementation.
- **Assurance:** coverage-guided fuzzing (10 targets), constant-time checks (valgrind, dudect),
  official test vectors, differential tests against RustCrypto, interop with OpenSSL, OpenSSH,
  WireGuard, libsodium, argon2-cffi, panva/jose, `coset`, cbor2 and Go `crypto/tls`.
- **Documentation:** threat model (docs/THREAT_MODEL.md), measured sizes and latency per profile
  (docs/PERFORMANCE.md, `cargo bench -p vpqc`), release procedure, shadow-mode and no-kill-switch
  decision (ADR-0015) with an incident-response procedure.
- **Migration aids:** `vpqc lint` (per-language replacement suggestions), `vpqc scan --format sarif`.
- **Release engineering:** reproducible static CLI (checked in CI), CycloneDX SBOMs and a CBOM per
  release.
- **Release engineering (workflow):** reproducible `--locked` builds; release workflow producing CLI
  binaries, C libraries, Python wheels, an npm package and a NuGet package with checksums and
  build provenance (docs/RELEASING.md).
- **Assurance:** Miri over the untrusted-input parsers (format, COSE/CBOR, SSH config) in CI; the
  CBOR half-float decoder no longer relies on `powi` for exact results.

### Not yet
- External security audit; FIPS 140-3 profile; composite X.509 certificates; registry publishing
  (`publish = false`).
