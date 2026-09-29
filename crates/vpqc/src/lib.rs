//! # vpqc: post-quantum cryptography with safe defaults
//!
//! Pick a [`Profile`]; the library picks vetted algorithms:
//!
//! | Profile | Encryption (KEM) | Signatures |
//! |---|---|---|
//! | [`Profile::Standard`] | X-Wing (X25519 + ML-KEM-768) | Ed25519 + ML-DSA-65 composite |
//! | [`Profile::FastAuth`] | X-Wing | Ed25519 (short-lived auth only) |
//! | [`Profile::Cnsa2`] | ML-KEM-1024 | ML-DSA-87 |
//!
//! ```
//! use vpqc::{Profile, encryption, signing};
//!
//! let keys = encryption::generate(Profile::Standard)?;
//! let sealed = encryption::seal(&keys.public, b"secret", b"ctx")?;
//! assert_eq!(encryption::open(&keys.secret, &sealed, b"ctx")?, b"secret");
//!
//! let keys = signing::generate(Profile::Standard)?;
//! let sig = signing::sign(&keys.secret, b"message", b"ctx")?;
//! signing::verify(&keys.public, b"message", b"ctx", &sig)?;
//! # Ok::<(), vpqc::Error>(())
//! ```
//!
//! **Pre-release, unaudited.** Do not use to protect real secrets yet.

pub mod encryption;
/// HPKE (RFC 9180bis) with post-quantum and hybrid KEMs, for protocols that need it
/// (MLS, ECH, OHTTP, ...). Most applications should use [`encryption`] instead.
pub use vpqc_hpke as hpke;
pub mod keys;
pub mod protect;
mod registry;
pub mod signing;
pub mod stream;

pub use registry::{kem, signature_scheme};
pub use vpqc_core::{
    AlgorithmId, Error, Kem, KemId, OsRng, Profile, PublicKey, RandomSource, Result, SecretKey,
    SharedSecret, SigId, SignatureScheme,
};

/// A freshly generated key pair.
#[derive(Debug)]
pub struct KeyPair {
    /// Public key: share it.
    pub public: PublicKey,
    /// Secret key: keep it private.
    pub secret: SecretKey,
}
