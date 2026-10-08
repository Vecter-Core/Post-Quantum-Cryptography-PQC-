# Implementation plan toward a defensible 1.0

Status: working plan, 2026-10-08. The project remains pre-release and unaudited.

## Working rules

1. Keep the Rust core and wire formats backward-compatible within a minor release.
2. Do not add an algorithm or protocol without a named standard, test vector, negative tests,
   interoperability evidence, and threat-model entry.
3. Every change must pass the narrowest relevant tests first, then the workspace gates.
4. Treat migration output as advice, never as an automatic source rewrite.
5. Record external limitations explicitly; do not turn test results into security guarantees.

## Phase A — establish a reproducible baseline

- [x] Sync the working branch with the latest project baseline.
- [x] Rust workspace test, clippy, fmt and release build pass in Codespaces.
- [x] C/C++ smoke and ABI checks pass.
- [ ] Run the complete CI-equivalent matrix locally or in CI and retain logs.
- [ ] Run `cargo test --workspace --all-targets --locked` and `cargo deny check` on the exact
      release commit.
- [ ] Run all language bindings and cross-language interop, not only Rust tests.
- [x] Add a CI version-consistency check for all release-facing bindings.
- [x] Reject a release tag whose version differs from the workspace version.
- [x] Verify native archive layout before checksums and attestations.
- [x] Verify Python, npm and NuGet package metadata before checksums and attestations.
- [x] Exclude repository metadata, generated artifacts and test-only trees from release CBOM input.

## Phase B — API, format and release hardening

- [ ] Audit public API and error-code stability.
- [x] Document format-version and profile-compatibility rules.
- [x] Cover sealed, signature, streaming and multi-recipient persisted formats with checked-in regression vectors and tamper tests.
- [ ] Add compatibility fixtures for protected secret keys and every remaining persisted format.
- [ ] Verify CLI exit codes, stdout/stderr separation, overwrite rules and secret redaction.
- [ ] Add shell completion and machine-readable output checks.
- [ ] Make release metadata and versions consistent across all bindings.
- [ ] Validate the release workflow with a dry run and reproducible-build checks.

## Phase C — migration and protocol completeness

- [ ] Verify `scan`, `lint`, SARIF and CBOM against real fixtures and schemas.
- [ ] Add X.509 CSR, CRL/OCSP and name-constraints only with explicit policy tests.
- [ ] Decide the supported COSE scope before implementing COSE_Sign/Encrypt/Mac extensions.
- [ ] Keep composite JOSE/X.509 behind an experimental feature until the target standard is stable.
- [ ] Add KMS/HSM abstraction tests; keep cloud/HSM integration tests opt-in.
- [ ] Add deployment examples for CLI, TLS sidecar and key rotation.

## Phase D — assurance and operations

- [ ] Extend fuzz campaigns, corpus retention and nightly runs.
- [ ] Extend constant-time coverage and publish reproducible benchmark reports.
- [ ] Add dependency audit/vet policy and multi-party reproducibility verification.
- [ ] Add incident-response, key-rotation, backup and recovery runbooks.
- [ ] Add release artifact verification documentation.
- [ ] Prepare an external audit package: threat model, API inventory, formats, test evidence,
      fuzz corpus, differential vectors and known limitations.

## Current work item

Start with Phase A's exact baseline and then review the newly added migration/release paths before
adding new cryptographic features. The first implementation slice is to make `vpqc scan`/`vpqc lint`
outputs testable against fixtures, because these are user-facing additions in the current baseline
and can fail independently of the cryptographic core.
