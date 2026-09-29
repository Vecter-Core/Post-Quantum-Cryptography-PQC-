# ADR-0008: JOSE with pure ML-DSA and `AKP` JWKs

- Status: accepted
- Date: 2026-09-29

## Context
JWS/JWT are the most common signed-token format in web systems (OAuth, OpenID Connect, API
tokens, verifiable credentials). Integrating post-quantum signatures there has more reach than
any vpqc-specific format.

The IETF is standardising ML-DSA for JOSE and COSE in draft-ietf-cose-dilithium: algorithm
names `ML-DSA-44/65/87`, a new key type `AKP` ("algorithm key pair") whose `pub` is the raw
public key and whose `priv` is the 32-byte seed, and pure ML-DSA with an empty context over the
JWS signing input. Independent implementations exist: panva's `jose` on Node.js WebCrypto
(backed by OpenSSL 3.5). Composite (hybrid) JOSE signatures are also drafted, but their
encoding is still changing.

## Decision
- New crate `vpqc-jose`: JWS compact serialization, JWT, `AKP` JWKs and RFC 7638 thumbprints,
  with `ML-DSA-65` (default) and `ML-DSA-87`. `ML-DSA-44` is not offered, as elsewhere in vpqc.
- **Pure ML-DSA, not composite.** Unlike vpqc's own signatures (ADR-0003), JOSE uses the
  standard algorithm so that any conforming verifier accepts the tokens. This is acceptable
  because ML-DSA is a NIST standard, and most tokens are short-lived. For long-lived signed
  objects that need hybrid assurance, use vpqc detached signatures. Composite JOSE will follow
  when its draft stabilises.
- Verification is strict:
  - the header `alg` must equal the key's algorithm, which rejects `none` and algorithm
    substitution (RFC 8725 section 3.1);
  - header and claims must have unique member names;
  - `crit` is rejected, since no extensions are implemented;
  - base64url must be canonical;
  - a public-key API refuses a JWK that contains `priv`.
- JWT validation per RFC 7519 and RFC 8725:
  - `exp` is required by default, and `nbf` is checked, with 60 s leeway;
  - `iss` is checked when configured;
  - a token carrying `aud` is accepted only by a verifier that identifies itself with one of
    its values;
  - explicit typing is supported through `typ`.
- A private JWK is validated by re-deriving the public key from `priv` and comparing it with
  `pub`.

## Consequences
- Tokens interoperate with other JOSE libraries. This is tested in CI against panva/jose on
  Node.js WebCrypto in both directions (`interop/jose.sh`).
- ML-DSA-65 signatures are 3309 bytes, so a JWT is about 4.5 KB. That fits in HTTP headers, but
  it is a large share of the usual 8 KB header limit. Deployments must check proxy and server
  limits, and prefer ML-DSA-65 over ML-DSA-87 for tokens sent in headers.
- The draft may still change: algorithm names, the `AKP` members, or the COSE identifiers.
  Such a change needs a new release; the code keeps these values in one place
  (`Algorithm::name`, `jwk.rs`).
