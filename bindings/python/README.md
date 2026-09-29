# vpqc (Python)

Post-quantum cryptography with safe defaults. Native core in Rust (libcrux ML-KEM/ML-DSA,
X-Wing hybrid KEM). **Pre-release, unaudited: do not protect real secrets with it yet.**

```python
import vpqc

# Public-key encryption: hybrid X25519 + ML-KEM-768 (X-Wing) + ChaCha20-Poly1305
keys = vpqc.generate_encryption_keypair()          # profile="standard"
sealed = vpqc.seal(keys.public, b"secret", aad=b"invoice-42")
assert vpqc.unseal(keys.secret, sealed, aad=b"invoice-42") == b"secret"

# Signatures: composite Ed25519 + ML-DSA-65 (both must verify), with a required context
signer = vpqc.generate_signing_keypair()
sig = vpqc.sign(signer.secret, b"release.tar.gz", context=b"my-app/release-v1")
vpqc.verify(signer.public, b"release.tar.gz", sig, context=b"my-app/release-v1")  # raises on failure
```

Profiles: `"standard"` (default), `"fast-auth"` (classical Ed25519 signatures, short-lived
authentication only), `"cnsa2"` (ML-KEM-1024 + ML-DSA-87).

Errors derive from `vpqc.VpqcError`: `DecryptionError`, `VerificationError`,
`InvalidInputError` (also a `ValueError`), `BackendError`.

Build: `pip install maturin && maturin develop --release`.
