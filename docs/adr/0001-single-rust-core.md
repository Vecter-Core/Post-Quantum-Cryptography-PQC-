# ADR-0001: One Rust core, thin per-language bindings

- Status: accepted
- Date: 2026-09-29

## Context
The project must offer a library for each language while NIST/IETF standards keep moving
(FIPS 206, HQC, composite signature drafts). Reimplementing crypto logic per language
multiplies the audit surface and makes the ecosystem drift apart.

## Decision
All cryptographic logic, wire formats and policy live in the Rust workspace. Each language
gets a thin binding (PyO3, WASM/napi-rs, C ABI, ...) that exposes idiomatic types but adds
no cryptography. A shared test-vector suite and cross-language interoperability tests gate
every release.

## Consequences
- A standards change is one code change plus a synchronized release.
- Bindings must not add `unsafe` to user code; the C ABI crate is the only place allowed to
  use `unsafe`, and it is reviewed separately.
- Some ecosystems already ship native PQC (Go `crypto/mlkem`, .NET). Bindings may delegate
  single primitives to those but must keep wire formats and policy identical to the core.
