//! Post-quantum JOSE: JWS and JWT signed with ML-DSA (FIPS 204), keys as `AKP` JWKs.
//!
//! Follows draft-ietf-cose-dilithium (ML-DSA for JOSE and COSE): algorithm names `ML-DSA-65` and
//! `ML-DSA-87`, key type `AKP` with `pub` (the raw public key) and `priv` (the 32-byte seed),
//! pure ML-DSA with an empty context over the JWS signing input (RFC 7515). JWT validation
//! follows RFC 7519 and the best practices of RFC 8725.
//!
//! ```
//! use vpqc_jose::{Algorithm, SigningKey, jwt};
//!
//! let key = SigningKey::generate(Algorithm::MlDsa65)?;
//! let mut claims = serde_json::Map::new();
//! claims.insert("sub".into(), "alice".into());
//! let token = jwt::encode(&key, claims, 300)?; // valid for 5 minutes
//!
//! let public = key.verifying_key();
//! let claims = jwt::decode(&token, &public, &jwt::Validation::default())?;
//! assert_eq!(claims["sub"], "alice");
//! # Ok::<(), vpqc_jose::Error>(())
//! ```
//!
//! **Size.** An ML-DSA-65 signature is 3309 bytes (4412 in base64url), so a JWT is about 4.5 KB.
//! Many servers and proxies limit a request header to 8 KB in total; check before sending such
//! tokens in `Authorization` headers.

mod error;
mod json;
pub mod jwk;
pub mod jws;
pub mod jwt;

pub use error::Error;
pub use jwk::{SigningKey, VerifyingKey};

use vpqc_backend_libcrux::mldsa::Level;

/// Result type of this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// A JWS algorithm.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Algorithm {
    /// `ML-DSA-65` (FIPS 204, NIST security category 3). The default.
    MlDsa65,
    /// `ML-DSA-87` (FIPS 204, category 5; CNSA 2.0).
    MlDsa87,
}

impl Algorithm {
    /// The JOSE `alg` name.
    pub const fn name(self) -> &'static str {
        match self {
            Algorithm::MlDsa65 => "ML-DSA-65",
            Algorithm::MlDsa87 => "ML-DSA-87",
        }
    }

    /// Parse a JOSE `alg` name (exact, case-sensitive match).
    pub fn from_name(name: &str) -> Result<Self> {
        match name {
            "ML-DSA-65" => Ok(Algorithm::MlDsa65),
            "ML-DSA-87" => Ok(Algorithm::MlDsa87),
            _ => Err(Error::UnsupportedAlgorithm(name.to_owned())),
        }
    }

    pub(crate) const fn level(self) -> Level {
        match self {
            Algorithm::MlDsa65 => Level::L65,
            Algorithm::MlDsa87 => Level::L87,
        }
    }

    /// Length of the raw public key in bytes.
    pub const fn public_key_len(self) -> usize {
        self.level().public_key_len()
    }

    /// Length of a signature in bytes.
    pub const fn signature_len(self) -> usize {
        self.level().signature_len()
    }
}

impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

pub(crate) mod b64 {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    pub fn encode(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Strict base64url: no padding, no whitespace, no non-zero trailing bits.
    pub fn decode(s: &str, what: &'static str) -> crate::Result<Vec<u8>> {
        URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|_| crate::Error::Malformed(what))
    }
}
