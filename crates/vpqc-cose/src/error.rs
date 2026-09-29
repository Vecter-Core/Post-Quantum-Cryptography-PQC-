use std::fmt;

/// Errors of COSE and CWT processing.
///
/// Verification failures are deliberately coarse: a bad signature, a wrong key, a wrong
/// external AAD and a modified message all give [`Error::VerificationFailed`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The message, header, key or claims are not well formed.
    Malformed(&'static str),
    /// The algorithm is not ML-DSA-65 or ML-DSA-87; the value is the COSE algorithm identifier.
    UnsupportedAlgorithm(i64),
    /// The message's algorithm differs from the key's algorithm.
    AlgorithmMismatch,
    /// The protected header lists critical parameters (`crit`) this library does not implement.
    UnsupportedCritical,
    /// The COSE_Key is invalid (wrong type, length, or `pub` does not match `priv`).
    InvalidKey(&'static str),
    /// The signature does not verify.
    VerificationFailed,
    /// A CWT claim check failed; the value names the claim (`exp`, `nbf`, `iss`, `aud`...).
    InvalidClaim(&'static str),
    /// The operating system random number generator failed.
    Rng,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Malformed(what) => write!(f, "malformed {what}"),
            Error::UnsupportedAlgorithm(alg) => write!(f, "unsupported COSE algorithm {alg}"),
            Error::AlgorithmMismatch => f.write_str("message algorithm does not match the key"),
            Error::UnsupportedCritical => f.write_str("unsupported critical header parameter"),
            Error::InvalidKey(why) => write!(f, "invalid key: {why}"),
            Error::VerificationFailed => f.write_str("signature verification failed"),
            Error::InvalidClaim(claim) => write!(f, "CWT claim check failed: {claim}"),
            Error::Rng => f.write_str("random number generator failure"),
        }
    }
}

impl std::error::Error for Error {}
