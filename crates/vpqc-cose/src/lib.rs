//! Post-quantum COSE (RFC 9052) and CWT (RFC 8392): `COSE_Sign1` signed with ML-DSA (FIPS 204),
//! keys as `AKP` COSE_Keys.
//!
//! Follows draft-ietf-cose-dilithium (ML-DSA for JOSE and COSE) with the IANA-registered values:
//! algorithms `ML-DSA-65` (-49) and `ML-DSA-87` (-50), key type `AKP` (7) with `pub` (-1, the
//! raw public key) and `priv` (-2, the 32-byte seed), pure ML-DSA with an empty context over
//! the `Sig_structure`. The binary counterpart of `vpqc-jose`, for constrained devices, IoT
//! and attestation.
//!
//! ```
//! use vpqc_cose::{Algorithm, SigningKey, cwt};
//!
//! let key = SigningKey::generate(Algorithm::MlDsa65)?;
//! let claims = cwt::Claims { sub: Some("sensor-17".into()), ..cwt::Claims::default() };
//! let token = cwt::encode(&key, claims, 3600)?; // valid for one hour
//!
//! let checked = cwt::decode(&token, &key.verifying_key(), &cwt::Validation::default())?;
//! assert_eq!(checked.sub.as_deref(), Some("sensor-17"));
//! # Ok::<(), vpqc_cose::Error>(())
//! ```
//!
//! **Size.** An ML-DSA-65 signature is 3309 bytes, so a CWT is about 3.4 KB (the public key,
//! 1952 bytes, travels separately). That is fine for CoAP with block-wise transfer or BLE with fragmentation, but not
//! for single-frame LoRaWAN or 802.15.4 payloads.

pub mod cbor;
pub mod cwt;
mod error;
pub mod key;
pub mod sign1;

pub use error::Error;
pub use key::{SigningKey, VerifyingKey};

use vpqc_backend_libcrux::mldsa::Level;

/// Result type of this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// A COSE signature algorithm.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Algorithm {
    /// `ML-DSA-65` (-49; FIPS 204, NIST security category 3). The default.
    MlDsa65,
    /// `ML-DSA-87` (-50; FIPS 204, category 5; CNSA 2.0).
    MlDsa87,
}

impl Algorithm {
    /// The IANA COSE algorithm identifier.
    pub const fn id(self) -> i64 {
        match self {
            Algorithm::MlDsa65 => -49,
            Algorithm::MlDsa87 => -50,
        }
    }

    /// The algorithm with this COSE identifier.
    pub fn from_id(id: i64) -> Result<Self> {
        match id {
            -49 => Ok(Algorithm::MlDsa65),
            -50 => Ok(Algorithm::MlDsa87),
            _ => Err(Error::UnsupportedAlgorithm(id)),
        }
    }

    /// The name, `ML-DSA-65` or `ML-DSA-87`.
    pub const fn name(self) -> &'static str {
        match self {
            Algorithm::MlDsa65 => "ML-DSA-65",
            Algorithm::MlDsa87 => "ML-DSA-87",
        }
    }

    pub(crate) const fn level(self) -> Level {
        match self {
            Algorithm::MlDsa65 => Level::L65,
            Algorithm::MlDsa87 => Level::L87,
        }
    }

    pub(crate) const fn public_key_len(self) -> usize {
        self.level().public_key_len()
    }

    pub(crate) const fn signature_len(self) -> usize {
        self.level().signature_len()
    }
}

impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Sort map entries by the bytewise order of their encoded keys (RFC 8949 section 4.2.1).
pub(crate) fn canonical_map(mut entries: Vec<(cbor::Value, cbor::Value)>) -> cbor::Value {
    entries.sort_by_cached_key(|(k, _)| cbor::encode(k));
    cbor::Value::Map(entries)
}
