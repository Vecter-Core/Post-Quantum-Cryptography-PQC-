# ADR-0006: SLH-DSA and the `archive` profile are deferred

- Status: accepted
- Date: 2026-09-29

## Context
The roadmap plans an `archive` profile: composite signatures plus SLH-DSA (FIPS 205) for
trust roots and long-term archives, where relying only on hash-function security is valuable.

The only Rust implementation available today is RustCrypto's `slh-dsa`, published as a
release candidate (`0.2.0-rc.5`). It has not been independently audited, and this project has
no second independent implementation to differential-test it against (unlike ML-KEM and
ML-DSA, where libcrux is checked against RustCrypto, see ADR-0002). NIST ACVP vectors could
not be fetched from this environment.

## Decision
Do **not** ship SLH-DSA yet, and do not ship a profile that silently depends on it. Revisit
when at least one of these holds:

1. `slh-dsa` reaches a stable release with an independent audit or a formally verified
   alternative appears (for example in libcrux), or
2. we can run the official ACVP vectors and a second implementation in CI.

Until then, long-lived signature needs are served by `standard`, `high` and `cnsa2`.
For firmware, LMS/XMSS (SP 800-208) remain a separate, later work item.

## Consequences
- `Profile::Archive` does not exist yet; roadmap items depending on it stay open.
- Nothing in the wire format prevents adding SLH-DSA later: signature ids are extensible.
