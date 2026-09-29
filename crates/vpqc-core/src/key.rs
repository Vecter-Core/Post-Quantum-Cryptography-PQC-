use core::fmt;
use zeroize::Zeroizing;

use crate::AlgorithmId;

/// Whether a serialized key is public or secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    /// Public (encapsulation / verification) key.
    Public,
    /// Secret (decapsulation / signing) key.
    Secret,
}

/// A public key tagged with its algorithm.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey {
    alg: AlgorithmId,
    bytes: Vec<u8>,
}

impl PublicKey {
    /// Wrap raw bytes. Length and validity are checked by the algorithm on use.
    pub fn new(alg: AlgorithmId, bytes: Vec<u8>) -> Self {
        Self { alg, bytes }
    }

    /// The algorithm this key belongs to.
    pub fn algorithm(&self) -> AlgorithmId {
        self.alg
    }

    /// Raw key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PublicKey({}, {} bytes)",
            self.alg.name(),
            self.bytes.len()
        )
    }
}

/// A secret key tagged with its algorithm. Zeroized on drop; never printed.
///
/// All `vpqc` secret keys are compact *seeds* (32 bytes for X-Wing, composite and ML-DSA,
/// 64 bytes for ML-KEM) from which the full key is re-derived on use.
pub struct SecretKey {
    alg: AlgorithmId,
    bytes: Zeroizing<Vec<u8>>,
}

impl SecretKey {
    /// Wrap raw seed bytes.
    pub fn new(alg: AlgorithmId, bytes: Vec<u8>) -> Self {
        Self {
            alg,
            bytes: Zeroizing::new(bytes),
        }
    }

    /// The algorithm this key belongs to.
    pub fn algorithm(&self) -> AlgorithmId {
        self.alg
    }

    /// Raw seed bytes. Handle with care.
    pub fn expose_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Clone for SecretKey {
    fn clone(&self) -> Self {
        Self {
            alg: self.alg,
            bytes: Zeroizing::new((*self.bytes).clone()),
        }
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretKey({}, <redacted>)", self.alg.name())
    }
}

/// A 32-byte shared secret. Zeroized on drop.
pub struct SharedSecret(Zeroizing<[u8; 32]>);

impl SharedSecret {
    /// Wrap 32 bytes.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Borrow the bytes.
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SharedSecret(<redacted>)")
    }
}
