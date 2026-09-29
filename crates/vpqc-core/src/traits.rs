use crate::{Error, KemId, PublicKey, RandomSource, Result, SecretKey, SharedSecret, SigId};

/// A freshly generated KEM key pair.
pub struct KemKeyPair {
    /// Public (encapsulation) key.
    pub public: PublicKey,
    /// Secret (decapsulation) key.
    pub secret: SecretKey,
}

/// A key-encapsulation mechanism producing a 32-byte shared secret.
pub trait Kem: Send + Sync {
    /// Algorithm identifier.
    fn id(&self) -> KemId;
    /// Public key length in bytes.
    fn public_key_len(&self) -> usize;
    /// Ciphertext length in bytes.
    fn ciphertext_len(&self) -> usize;
    /// Generate a key pair.
    fn generate(&self, rng: &mut dyn RandomSource) -> Result<KemKeyPair>;
    /// Encapsulate to `pk`, returning `(ciphertext, shared_secret)`.
    fn encapsulate(
        &self,
        pk: &PublicKey,
        rng: &mut dyn RandomSource,
    ) -> Result<(Vec<u8>, SharedSecret)>;
    /// Decapsulate `ciphertext` with `sk`.
    ///
    /// ML-KEM uses implicit rejection: a corrupted ciphertext yields an unrelated
    /// shared secret rather than an error, so a wrong key surfaces later, when the
    /// AEAD tag fails.
    fn decapsulate(&self, sk: &SecretKey, ciphertext: &[u8]) -> Result<SharedSecret>;
}

/// A digital signature scheme with domain-separation context.
pub trait SignatureScheme: Send + Sync {
    /// Algorithm identifier.
    fn id(&self) -> SigId;
    /// Signature length in bytes.
    fn signature_len(&self) -> usize;
    /// Generate `(public, secret)` keys.
    fn generate(&self, rng: &mut dyn RandomSource) -> Result<(PublicKey, SecretKey)>;
    /// Sign `message` under `context` (at most 255 bytes).
    fn sign(
        &self,
        sk: &SecretKey,
        message: &[u8],
        context: &[u8],
        rng: &mut dyn RandomSource,
    ) -> Result<Vec<u8>>;
    /// Verify `signature` over `message` under `context`.
    fn verify(
        &self,
        pk: &PublicKey,
        message: &[u8],
        context: &[u8],
        signature: &[u8],
    ) -> Result<()>;
}

pub(crate) fn _assert_object_safe(_: &dyn Kem, _: &dyn SignatureScheme) {}

impl Error {
    /// Helper to build a length error.
    pub fn length(what: &'static str, expected: usize, actual: usize) -> Self {
        Error::InvalidLength {
            what,
            expected,
            actual,
        }
    }
}
