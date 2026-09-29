use std::fmt;

/// Errors of JOSE processing.
///
/// Verification failures are deliberately coarse: a bad signature, a wrong key and a
/// modified token all give [`Error::VerificationFailed`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The token, header or JWK is not well formed.
    Malformed(&'static str),
    /// The `alg` is not supported (or is `none`).
    UnsupportedAlgorithm(String),
    /// The token's `alg` differs from the key's algorithm.
    AlgorithmMismatch,
    /// The header lists critical extensions (`crit`) this library does not implement.
    UnsupportedCritical,
    /// The JWK is invalid (wrong type, length, or `pub` does not match `priv`).
    InvalidKey(&'static str),
    /// The signature does not verify.
    VerificationFailed,
    /// A JWT claim check failed; the value names the claim (`exp`, `nbf`, `iss`, `aud`, `typ`).
    InvalidClaim(&'static str),
    /// The operating system random number generator failed.
    Rng,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Malformed(what) => write!(f, "malformed {what}"),
            Error::UnsupportedAlgorithm(alg) => write!(f, "unsupported JWS algorithm {alg:?}"),
            Error::AlgorithmMismatch => f.write_str("token algorithm does not match the key"),
            Error::UnsupportedCritical => f.write_str("unsupported critical header parameter"),
            Error::InvalidKey(why) => write!(f, "invalid key: {why}"),
            Error::VerificationFailed => f.write_str("signature verification failed"),
            Error::InvalidClaim(claim) => write!(f, "JWT claim check failed: {claim}"),
            Error::Rng => f.write_str("random number generator failure"),
        }
    }
}

impl std::error::Error for Error {}
