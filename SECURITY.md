# Security policy

**vpqc is pre-release (0.0.x) and has not been audited.** Do not use it to protect real
secrets yet. Constant-time behaviour is inherited from the backends and has been checked by
this project with secret tracking under valgrind and timing measurements (tools/ct-check:
evidence, not proof); it has not been reviewed by a third party. See docs/THREAT_MODEL.md for
what is and is not in scope.

## Reporting a vulnerability

Please report privately using GitHub's *Report a vulnerability* button (Security tab of the
repository). Do not open a public issue. Include the affected version, a reproduction and,
if possible, a suggested fix. We aim to acknowledge reports within 3 working days.

## Scope

In scope: cryptographic flaws in constructions (X-Wing usage, composite signatures,
envelopes, KDF binding), parser bugs in `vpqc-format`, key-handling mistakes (leaks, missing
zeroization), API misuse traps. Vulnerabilities in third-party backends should also be
reported upstream (libcrux, RustCrypto, dalek).

## Supported versions

Only the latest release. There is no stable release yet.
