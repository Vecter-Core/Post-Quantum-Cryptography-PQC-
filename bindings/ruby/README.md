# vpqc (Ruby)

Post-quantum cryptography with safe defaults, over the Rust core's C ABI.
**Pre-release, unaudited: do not protect real secrets with it yet.**

```ruby
require "vpqc"

keys   = Vpqc.generate_encryption_keypair            # profile :standard (X-Wing)
sealed = Vpqc.seal(keys.public, "secret", aad: "invoice-42")
Vpqc.unseal(keys.secret, sealed, aad: "invoice-42")  # => "secret"

signer = Vpqc.generate_signing_keypair               # Ed25519 + ML-DSA-65 composite
sig = Vpqc.sign(signer.secret, "release.tar.gz", context: "my-app/release-v1")
Vpqc.verify(signer.public, "release.tar.gz", sig, context: "my-app/release-v1") # raises if invalid
Vpqc.valid?(signer.public, "release.tar.gz", sig, context: "my-app/release-v1") # => true
```

Set `VPQC_LIBRARY` to the path of `libvpqc_ffi.so` / `.dylib` / `vpqc_ffi.dll`
(`cargo build -p vpqc-ffi --release`). Errors: `Vpqc::DecryptionError`,
`Vpqc::VerificationError`, `Vpqc::InvalidInputError` (all `Vpqc::Error`).
