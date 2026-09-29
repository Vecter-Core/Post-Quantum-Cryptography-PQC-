//! Post-quantum X.509: ML-DSA keys, certificates and chain verification.
//!
//! Encodings follow RFC 9881 (ML-DSA in X.509, formerly draft-ietf-lamps-dilithium-certificates):
//! algorithm identifiers `id-ml-dsa-65` /
//! `id-ml-dsa-87` without parameters, the raw public key in `SubjectPublicKeyInfo`, pure ML-DSA
//! with an empty context over the DER `TBSCertificate`, and PKCS#8 private keys holding the
//! 32-byte seed. Interoperability is tested against OpenSSL (through Python `cryptography` and
//! Node.js).
//!
//! ```
//! use vpqc_x509::{Algorithm, CertificateParams, PrivateKey, Purpose, verify_chain, VerifyOptions};
//!
//! let ca_key = PrivateKey::generate(Algorithm::MlDsa87)?;
//! let ca = CertificateParams::ca("Example Root CA", 3650).self_signed(&ca_key)?;
//!
//! let server_key = PrivateKey::generate(Algorithm::MlDsa65)?;
//! let leaf = CertificateParams::end_entity("api.example.com", 90)
//!     .dns_names(&["api.example.com"])
//!     .purpose(Purpose::ServerAuth)
//!     .issue(server_key.public_key(), &ca, &ca_key)?;
//!
//! verify_chain(&leaf, &[], &[ca], &VerifyOptions::for_dns_name("api.example.com"))?;
//! # Ok::<(), vpqc_x509::Error>(())
//! ```
//!
//! **Scope.** [`verify_chain`] is a deliberately small path validator for chains that are
//! ML-DSA end to end (see its documentation). It is not a replacement for a full RFC 5280
//! validator such as webpki in general-purpose TLS clients.

mod cert;
mod der;
mod key;
mod parse;
mod pem;
mod verify;

pub use cert::{Certificate, CertificateParams, Purpose};
pub use key::{PrivateKey, PublicKey};
pub use verify::{VerifyOptions, verify_chain};

use vpqc_backend_libcrux::mldsa::Level;

/// Result type of this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The encoding (DER, PEM, certificate) is malformed.
    Malformed(&'static str),
    /// The algorithm is not ML-DSA-65 or ML-DSA-87.
    UnsupportedAlgorithm(String),
    /// A key is invalid (wrong length, inconsistent seed and expanded key...).
    InvalidKey(&'static str),
    /// A signature does not verify.
    BadSignature,
    /// The chain is not valid; the text says why.
    InvalidChain(&'static str),
    /// Certificate parameters are invalid.
    InvalidParams(&'static str),
    /// The operating system random number generator failed.
    Rng,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Malformed(what) => write!(f, "malformed {what}"),
            Error::UnsupportedAlgorithm(oid) => write!(f, "unsupported algorithm {oid}"),
            Error::InvalidKey(why) => write!(f, "invalid key: {why}"),
            Error::BadSignature => f.write_str("signature verification failed"),
            Error::InvalidChain(why) => write!(f, "certificate chain rejected: {why}"),
            Error::InvalidParams(why) => write!(f, "invalid certificate parameters: {why}"),
            Error::Rng => f.write_str("random number generator failure"),
        }
    }
}

impl std::error::Error for Error {}

impl<E> From<x509_parser::nom::Err<E>> for Error {
    fn from(_: x509_parser::nom::Err<E>) -> Self {
        Error::Malformed("DER structure")
    }
}

/// A signature algorithm.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Algorithm {
    /// ML-DSA-65 (FIPS 204, category 3).
    MlDsa65,
    /// ML-DSA-87 (FIPS 204, category 5; CNSA 2.0).
    MlDsa87,
}

/// `2.16.840.1.101.3.4.3.18` / `.19` (NIST sigAlgs arc).
const OID_ML_DSA_65: [u8; 9] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12];
const OID_ML_DSA_87: [u8; 9] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13];

impl Algorithm {
    /// Name as in RFC 9881.
    pub const fn name(self) -> &'static str {
        match self {
            Algorithm::MlDsa65 => "ML-DSA-65",
            Algorithm::MlDsa87 => "ML-DSA-87",
        }
    }

    /// Parse `ML-DSA-65` / `ML-DSA-87`.
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

    const fn oid_content(self) -> &'static [u8] {
        match self {
            Algorithm::MlDsa65 => &OID_ML_DSA_65,
            Algorithm::MlDsa87 => &OID_ML_DSA_87,
        }
    }

    /// DER `AlgorithmIdentifier` (parameters absent).
    pub(crate) fn algorithm_identifier(self) -> Vec<u8> {
        der::seq(&[&der::oid(self.oid_content())])
    }

    pub(crate) fn from_oid_content(oid: &[u8]) -> Result<Self> {
        if oid == OID_ML_DSA_65 {
            Ok(Algorithm::MlDsa65)
        } else if oid == OID_ML_DSA_87 {
            Ok(Algorithm::MlDsa87)
        } else {
            Err(Error::UnsupportedAlgorithm(format!(
                "OID {}",
                oid.iter().map(|b| format!("{b:02x}")).collect::<String>()
            )))
        }
    }

    pub(crate) fn from_identifier(id: &x509_parser::x509::AlgorithmIdentifier<'_>) -> Result<Self> {
        if id.parameters.is_some() {
            return Err(Error::Malformed(
                "ML-DSA AlgorithmIdentifier must not have parameters",
            ));
        }
        Self::from_oid_content(id.algorithm.as_bytes())
            .map_err(|_| Error::UnsupportedAlgorithm(id.algorithm.to_id_string()))
    }
}

impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}
