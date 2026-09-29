//! Core types for `vpqc`: algorithm identifiers, profiles, key containers,
//! the [`Kem`] / [`SignatureScheme`] traits, randomness sources and errors.
//!
//! This crate contains **no cryptographic primitives**. Concrete algorithms live in
//! `vpqc-backend-libcrux` (ML-KEM, ML-DSA) and `vpqc-hybrid` (X-Wing, composite
//! signatures).

mod error;
mod id;
mod key;
mod profile;
mod rng;
mod traits;

pub use error::{Error, Result};
pub use id::{AeadId, AlgorithmId, KemId, SigId};
pub use key::{KeyKind, PublicKey, SecretKey, SharedSecret};
pub use profile::Profile;
pub use rng::{OsRng, RandomSource};
pub use traits::{Kem, KemKeyPair, SignatureScheme};

#[doc(hidden)]
pub use rng::testing;
