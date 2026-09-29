use core::fmt;

/// Result alias used across `vpqc`.
pub type Result<T> = core::result::Result<T, Error>;

/// Errors returned by `vpqc`.
///
/// Errors on the decryption / verification path are deliberately coarse so they do not
/// act as oracles: a tampered ciphertext, a wrong key and a wrong context all report the
/// same [`Error::DecryptionFailed`] (or [`Error::VerificationFailed`]).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The operating system random number generator failed.
    Rng,
    /// An input had an unexpected length.
    InvalidLength {
        /// What was being parsed.
        what: &'static str,
        /// Expected length in bytes.
        expected: usize,
        /// Actual length in bytes.
        actual: usize,
    },
    /// A key is malformed or fails a validity check.
    InvalidKey(&'static str),
    /// A key or object belongs to a different algorithm than the operation requires.
    AlgorithmMismatch,
    /// The algorithm / profile is unknown or not compiled in.
    Unsupported(&'static str),
    /// Serialized data (envelope, armored key) is malformed.
    Format(&'static str),
    /// Encapsulation or key generation failed inside a backend.
    Backend(&'static str),
    /// Decryption failed (wrong key, wrong context, or tampered data).
    DecryptionFailed,
    /// Signature verification failed.
    VerificationFailed,
    /// A signing context longer than 255 bytes was supplied.
    ContextTooLong,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Rng => f.write_str("random number generator failure"),
            Error::InvalidLength {
                what,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "invalid length for {what}: expected {expected} bytes, got {actual}"
                )
            }
            Error::InvalidKey(why) => write!(f, "invalid key: {why}"),
            Error::AlgorithmMismatch => f.write_str("algorithm mismatch"),
            Error::Unsupported(what) => write!(f, "unsupported: {what}"),
            Error::Format(why) => write!(f, "malformed data: {why}"),
            Error::Backend(why) => write!(f, "backend error: {why}"),
            Error::DecryptionFailed => f.write_str("decryption failed"),
            Error::VerificationFailed => f.write_str("signature verification failed"),
            Error::ContextTooLong => f.write_str("signing context longer than 255 bytes"),
        }
    }
}

impl std::error::Error for Error {}
