# Format and compatibility policy

Status: pre-release (`0.0.x`), format version 1, 2026-10-08.

## Scope

The binary objects produced by `vpqc-format` start with the four-byte magic `VPQC`, a one-byte
format version, and a one-byte object kind. The current format version is **1**. The version is
authenticated as part of the envelope/signature constructions where applicable; it is not a
user-selectable algorithm switch.

Persisted objects include public/secret keys, sealed messages, detached signatures, protected
secret keys, and streaming envelopes. The exact layouts are implemented in `crates/vpqc-format`
and are covered by checked-in vectors and parser robustness tests.

## Compatibility rules

- A patch release must continue reading every valid format-1 object produced by an earlier patch
  release.
- A minor pre-1.0 release may add new object kinds or optional authenticated fields, but must not
  silently reinterpret an existing kind or algorithm identifier.
- An incompatible layout requires a new format version and an explicit migration path. Parsers must
  reject an unknown version; they must never guess or downgrade.
- Algorithm/profile identifiers are authenticated. Changing an identifier, profile or KEM
  ciphertext must fail authentication rather than select a fallback.
- Public and secret key encodings are separate kinds. A parser must not accept one as the other.
- Protected secret-key objects must not expose the underlying key in error messages, reports or
  inspection output.
- Removing a recipient from a rewrapped envelope is not revocation: a recipient that already
  decrypted the file key keeps access to plaintext previously obtained.

## Release checklist

Before a release, run the workspace tests with `--locked --all-targets` and verify the checked-in
format vectors. For a format change, add all of the following in the same change:

1. A format-version/compatibility note and an ADR if the threat model changes.
2. A valid-object fixture and a malformed/tampered fixture.
3. A test proving old supported objects still parse, or an explicit versioned migration test.
4. A test proving algorithm/profile relabelling fails authentication.
5. Cross-language interop coverage for every binding that reads or writes the changed object.
6. An update to `CHANGELOG.md`, `docs/THREAT_MODEL.md` and this document.

This policy describes intended compatibility. It is not a security guarantee and does not replace
an external review.
