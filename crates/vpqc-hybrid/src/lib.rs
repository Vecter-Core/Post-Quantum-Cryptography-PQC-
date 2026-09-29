//! Hybrid constructions.
//!
//! * [`XWing`]: the X-Wing KEM (X25519 + ML-KEM-768), implemented exactly as
//!   specified in `draft-connolly-cfrg-xwing-kem` and checked against its official test
//!   vectors. It stays secure if *either* X25519 or ML-KEM-768 holds.
//! * [`Ed25519`] and [`CompositeEd25519MlDsa65`]: classical and composite signatures.
//!   The composite requires **both** signatures to verify.

mod composite;
mod ed25519;
mod shake;
pub mod xwing;

pub use composite::CompositeEd25519MlDsa65;
pub use ed25519::Ed25519;
pub use xwing::XWing;
