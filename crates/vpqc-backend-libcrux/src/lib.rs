//! ML-KEM (FIPS 203) and ML-DSA (FIPS 204) backed by
//! [libcrux](https://github.com/cryspen/libcrux), which is formally verified for
//! panic freedom, functional correctness and secret independence.
//!
//! Two layers:
//! * [`mlkem`] / [`mldsa`]: byte-level primitives with **explicit randomness**, used by
//!   `vpqc-hybrid` and by known-answer tests.
//! * [`MlKem768`], [`MlKem1024`], [`MlDsa65`], [`MlDsa87`]: implementations of the
//!   `vpqc-core` traits. Secret keys are stored as compact seeds (64 bytes for ML-KEM:
//!   `d || z`, 32 bytes for ML-DSA: `xi`) and re-expanded on use.
//!
//! Limitation: intermediate expanded keys held inside libcrux types are not zeroized
//! by this crate (libcrux does not expose `Zeroize`). Long-term storage uses seeds only.

pub mod mldsa;
pub mod mlkem;
mod schemes;

pub use schemes::{MlDsa65, MlDsa87, MlKem768, MlKem1024};
