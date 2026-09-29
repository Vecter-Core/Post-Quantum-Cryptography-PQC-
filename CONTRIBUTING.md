# Contributing

Read `docs/ROADMAP.md` and `docs/adr/` first: they explain what is decided and why.

## Ground rules
- **No new cryptographic primitives.** Use a backend behind `Kem` / `SignatureScheme`
  (ADR-0002). Constructions on top need an ADR and known-answer or differential tests.
- No `unsafe` in library crates (`unsafe_code = "forbid"` is set workspace-wide).
- Errors on decryption/verification paths must stay coarse (no oracles).
- Secrets: wrap in `Zeroizing` / `SecretKey`, never derive `Debug` that prints them.
- Every parser change needs a test that feeds truncated and bit-flipped input.

## Before you push
```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
CI runs the same plus `cargo deny check`.

## Commit sign-off
Use `git commit -s` (Developer Certificate of Origin). Contributions are licensed under
Apache-2.0.
