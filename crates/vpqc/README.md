# vpqc

Post-quantum cryptography with safe defaults. Pick a **profile**, not an algorithm.

```rust
use vpqc::{Profile, encryption, signing};

// Encrypt to a recipient (hybrid X25519 + ML-KEM-768, X-Wing).
let keys = encryption::generate(Profile::Standard)?;
let sealed = encryption::seal(&keys.public, b"secret", b"context")?;
let plain = encryption::open(&keys.secret, &sealed, b"context")?;
assert_eq!(plain, b"secret");

// Sign (composite Ed25519 + ML-DSA-65: both must verify).
let keys = signing::generate(Profile::Standard)?;
let sig = signing::sign(&keys.secret, b"release.tar.gz", b"my-app/release")?;
signing::verify(&keys.public, b"release.tar.gz", b"my-app/release", &sig)?;
# Ok::<(), vpqc::Error>(())
```

**Status: pre-release (0.0.x). Not audited. Do not protect real secrets with it yet.**
See `docs/ROADMAP.md` in the repository.
