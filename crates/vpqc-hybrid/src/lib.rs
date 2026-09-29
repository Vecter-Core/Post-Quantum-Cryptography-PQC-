//! Hybrid constructions.
//!
//! * [`XWing`]: the X-Wing KEM (X25519 + ML-KEM-768), implemented exactly as
//!   specified in `draft-connolly-cfrg-xwing-kem` and checked against its official test
//!   vectors. It stays secure if *either* X25519 or ML-KEM-768 holds.
//! * [`MlKem1024P384`]: the `MLKEM1024-P384` hybrid KEM (draft-irtf-cfrg-concrete-hybrid-kems),
//!   also checked against its official test vectors.
//! * [`Ed25519`], [`CompositeEd25519MlDsa65`] and [`CompositeEcdsaP384MlDsa87`]: classical and
//!   composite signatures.
//!   The composite requires **both** signatures to verify.

mod composite;
mod ed25519;
pub mod mlkem1024_p384;
mod p384_sig;
mod shake;
pub mod xwing;

pub use composite::{ClassicalHalf, Composite, CompositeEd25519MlDsa65, Ed25519Half, ExpandedSeed};
pub use ed25519::Ed25519;
pub use mlkem1024_p384::MlKem1024P384;
pub use p384_sig::{CompositeEcdsaP384MlDsa87, EcdsaP384Half};
pub use xwing::XWing;
