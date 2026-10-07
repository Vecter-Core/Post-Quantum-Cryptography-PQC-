# Threat model

Scope: what vpqc protects against, what it does not, and which assumptions its guarantees rest
on. Pre-release and **unaudited**: this document states the design intent and the evidence
collected so far, not a security guarantee.

## 1. Assets and adversaries

| Asset | Examples |
|---|---|
| Confidentiality of data in transit or at rest | sealed boxes, encrypted files, VPN tunnels, SSH sessions |
| Authenticity and integrity | signatures, JWT/CWT, certificates, firmware |
| Secret keys | encryption and signing keys, KEKs, passphrases |

| Adversary | Capability | In scope |
|---|---|---|
| **A1 passive, harvest-now-decrypt-later** | Records traffic and files today; later has a quantum computer (CRQC) | **Yes, the main target** (key establishment, ADR-0003) |
| **A2 classical active** | Modifies, replays, reorders, truncates, splices, substitutes algorithms | Yes |
| **A3 future quantum, forging** | Forges signatures after the signing key's lifetime | Yes for long-lived signatures; short-lived authentication may stay classical (tier T2) |
| **A4 cryptanalytic surprise** | A break of ML-KEM or ML-DSA alone, or of X25519/Ed25519 alone | Yes: this is why default profiles are hybrid / composite |
| **A5 malicious input** | Crafted files, certificates, configs, network messages | Yes (parsers: strict, fuzzed) |
| **A6 local attacker with file access** | Reads key files, backups, disk images | Partly: keys can be encrypted at rest (ADR-0013); a compromised running host is out of scope |
| **A7 side channels** | Timing, cache, power, fault injection | Partly: see section 4 |
| **A8 supply chain** | Malicious or vulnerable dependency, tampered release | Partly: section 5 |

## 2. Design responses

- **Hybrid by risk tier** (ADR-0003). Key establishment is hybrid (X25519 + ML-KEM-768 as
  X-Wing; P-384 + ML-KEM-1024 for `high`); signatures in `standard` are composite
  (Ed25519 + ML-DSA-65: both must verify). A break of one component does not break the whole
  (A4). Long-lived signature trust anchors default to ML-DSA-87 where interop allows.
- **No algorithm negotiation, no downgrade.** The algorithm identifier is inside the
  authenticated data (header and KEM ciphertext feed the KDF and the AEAD associated data,
  ADR-0005); the verifier's key decides the signature algorithm. Tested by relabelling
  mutations (A2).
- **Strict parsing.** One encoding per object, no trailing data, bounded lengths, parameters in
  fixed ranges; coverage-guided fuzzing of every parser and untrusted-input path with injected-bug
  validation of the fuzz targets (A5).
- **Streaming and envelopes** (ADR-0007, ADR-0009). STREAM construction against truncation,
  reordering and splicing; multi-recipient header MAC keyed by the file key, which commits to it
  and prevents a sender from giving different recipients different plaintexts ("invisible
  salamanders").
- **Misuse resistance.** Signatures require a context. Hedged signatures, no raw nonces in the
  API, secret keys stored as seeds (ADR-0004), verification failures are not distinguishable
  (`DecryptionFailed`, `VerificationFailed`) to avoid oracles.
- **Keys at rest** (ADR-0013): Argon2id passphrase or KMS/TPM-wrapped key; secret keys zeroized on
  drop in the Rust core (and in native buffers freed through the C ABI).
- **Interop over invention.** Wherever a standard exists (JOSE, COSE, X.509, SSH, WireGuard,
  TLS), vpqc uses it and is tested against independent implementations; it does not define new
  protocols.

## 3. Explicit non-goals and known limits

- **Not audited.** No claim of FIPS 140-3 validation. The ML-KEM/ML-DSA backend (libcrux) is
  formally verified in parts upstream; vpqc's compositions and formats are not.
- **No protection against a compromised host.** Malware or a debugger can read keys from memory.
  Language runtimes without deterministic memory (Python, JavaScript, Java, PHP, Ruby, .NET,
  Dart) cannot guarantee that no copy of a key remains in memory.
- **Authenticity of a sealed box's sender is not provided** by `seal`: anyone with the public key
  can seal. Use `sign` as well, or an authenticated channel. (WireGuard PSK delivery signs
  explicitly for this reason, ADR-0014.)
- **No forward secrecy for stored data.** Sealed boxes and files do not ratchet. A later
  compromise of a recipient's secret key opens everything sealed to it. Rotate keys; use
  `rewrap` for envelope files. Removing a recipient does not revoke what they already read.
- **Metadata** (sizes, timing, recipient counts, algorithm identifiers) is not hidden.
- **Revocation and policy** in the X.509 verifier are minimal: no CRL/OCSP, no name constraints
  (ADR-0010). It is not a replacement for a full path validator.
- **Static VPN PSKs** have no forward secrecy (ADR-0014); Rosenpass is the better tool where it
  can run.
- **Large sizes.** ML-DSA signatures (3.3 to 4.6 KB) and certificate chains (~14 KB) do not fit
  every protocol or constrained link; see docs/PERFORMANCE.md.
- **Denial of service** by expensive inputs is mitigated, not eliminated: Argon2 parameters are
  bounded, parsers allocate only against input length, but a caller who decrypts untrusted
  large files still spends the CPU.

## 4. Side channels

Evidence collected (see `tools/ct-check/README.md`; evidence, not proof):

- **Secret tracking under valgrind** (ctgrind, gates CI): ML-KEM-768/1024 decapsulation, X25519,
  Ed25519 signing and ChaCha20-Poly1305 are clean: no branch and no memory address depends on
  secret bytes. X-Wing, MLKEM1024-P384, ML-DSA-65 and ECDSA-P384 show only documented, allowlisted
  conditions (rejection sampling on public data, FIPS 204 rejection conditions, ~2^-384
  validity checks, one upstream compiler-introduced branch).
- **dudect-style timing** with deliberately leaky controls that must be detected, on pools of
  valid vs corrupted ciphertexts (implicit rejection must not reveal validity).
- **Build configuration matters:** `overflow-checks` in dependencies added branches on secrets;
  the release profile now disables them for dependencies.

Not covered yet: ML-DSA-87 signing, HPKE and the protected-key, JOSE/COSE and X.509 code paths
are not tracked individually (they reuse the primitives above); FN-DSA is not implemented.
Open items: cycle-accurate measurement on bare metal; power/EM/fault attacks (out of scope for software on general-purpose hardware;
embedded users need hardware countermeasures); a second implementation to compare timing.

## 5. Supply chain and release

- `cargo deny` (advisories, licenses, bans, sources) gates CI; `Cargo.lock` is committed and
  builds use `--locked`; the MSRV is checked.
- Dependencies handling secrets are few and mainstream: libcrux (ML-KEM, ML-DSA, SHA-3), dalek
  (X25519, Ed25519), RustCrypto (P-384, ChaCha20-Poly1305, Argon2), aws-lc-rs/rustls (TLS).
  The RustCrypto ML-KEM/ML-DSA crates are used as an independent differential-test oracle.
- Releases (docs/RELEASING.md): checksums and build provenance attestations; an SBOM and a CBOM
  accompany each release.
- Not done: `cargo vet` audits of dependencies; multi-party reproducibility verification.

## 6. Where assurance comes from

| Claim | Evidence |
|---|---|
| ML-KEM / ML-DSA correct | NIST ACVP vectors (250/250), byte-for-byte differential tests against RustCrypto |
| X-Wing, MLKEM1024-P384 correct | Official draft test vectors |
| Formats and parsers robust | Fuzzing (10 targets), mutation tests, strict one-encoding rule |
| Interop | OpenSSL, OpenSSH, WireGuard, libsodium, argon2-cffi, panva/jose, `coset`, cbor2, Go crypto/tls; 9-language matrix |
| No secret-dependent branches | ctgrind + dudect (section 4) |
| Misuse traps | Negative tests for every mutation and mismatch in the test suites |

What is **missing** is independent review: an external cryptography audit is the gate before
any use with real secrets.
