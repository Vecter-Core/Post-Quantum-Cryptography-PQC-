//! Public-key encryption ("sealed box"): encrypt to a recipient's public key.
//!
//! `KEM(recipient) -> shared secret -> SHAKE256 -> (key, nonce) -> ChaCha20-Poly1305`.
//! The KDF input and the AEAD associated data both include the envelope header and the
//! KEM ciphertext, so the algorithm identifiers cannot be altered without detection.
//! Each message uses a fresh KEM shared secret, so the derived key/nonce pair is unique.
//!
//! This is anonymous encryption: it does not authenticate the sender. Sign the
//! plaintext (or use the `aad` context) if the recipient needs to know who sent it.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use vpqc_core::{
    AeadId, AlgorithmId, Error, OsRng, Profile, PublicKey, RandomSource, Result, SecretKey,
};
use vpqc_format::Sealed;
use zeroize::Zeroizing;

use crate::{KeyPair, registry};

const KDF_LABEL: &[u8] = b"vpqc-seal-v1";

/// Generate an encryption key pair for `profile`.
pub fn generate(profile: Profile) -> Result<KeyPair> {
    generate_with(profile, &mut OsRng)
}

/// [`generate`] with an explicit randomness source (for tests).
pub fn generate_with(profile: Profile, rng: &mut dyn RandomSource) -> Result<KeyPair> {
    let pair = registry::kem(profile.kem())?.generate(rng)?;
    Ok(KeyPair {
        public: pair.public,
        secret: pair.secret,
    })
}

/// Derive `(key, nonce)` from the KEM shared secret and the authenticated header.
fn derive(prefix: &[u8], shared_secret: &[u8; 32]) -> (Zeroizing<[u8; 32]>, [u8; 12]) {
    let mut input = Zeroizing::new(Vec::with_capacity(KDF_LABEL.len() + 8 + prefix.len() + 32));
    input.extend_from_slice(KDF_LABEL);
    input.extend_from_slice(&(prefix.len() as u64).to_be_bytes());
    input.extend_from_slice(prefix);
    input.extend_from_slice(shared_secret);
    let mut out = Zeroizing::new([0u8; 44]);
    libcrux_sha3::shake256_ema(&mut *out, &input);
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&out[..32]);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&out[32..]);
    (key, nonce)
}

fn full_aad(prefix: &[u8], aad: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(prefix.len() + aad.len());
    v.extend_from_slice(prefix);
    v.extend_from_slice(aad);
    v
}

/// Encrypt `plaintext` to `recipient`. `aad` is authenticated context that the
/// recipient must supply again to open the message (it is not stored).
pub fn seal(recipient: &PublicKey, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    seal_with(recipient, plaintext, aad, &mut OsRng)
}

/// [`seal`] with an explicit randomness source (for tests).
pub fn seal_with(
    recipient: &PublicKey,
    plaintext: &[u8],
    aad: &[u8],
    rng: &mut dyn RandomSource,
) -> Result<Vec<u8>> {
    let AlgorithmId::Kem(kem_id) = recipient.algorithm() else {
        return Err(Error::AlgorithmMismatch);
    };
    let (kem_ct, ss) = registry::kem(kem_id)?.encapsulate(recipient, rng)?;
    let mut sealed = Sealed {
        kem: kem_id,
        aead: AeadId::ChaCha20Poly1305,
        kem_ciphertext: kem_ct,
        body: Vec::new(),
    };
    let prefix = sealed.header_and_kem_ciphertext();
    let (key, nonce) = derive(&prefix, ss.expose());
    let cipher =
        ChaCha20Poly1305::new_from_slice(&*key).map_err(|_| Error::Backend("bad AEAD key"))?;
    sealed.body = cipher
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: plaintext,
                aad: &full_aad(&prefix, aad),
            },
        )
        .map_err(|_| Error::Backend("AEAD encryption failed"))?;
    Ok(sealed.encode())
}

/// Decrypt a message produced by [`seal`].
///
/// Returns [`Error::DecryptionFailed`] for a wrong key, wrong `aad`, or any tampering.
pub fn open(secret: &SecretKey, sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let sealed = Sealed::decode(sealed)?;
    if secret.algorithm() != AlgorithmId::Kem(sealed.kem) {
        return Err(Error::AlgorithmMismatch);
    }
    let ss = registry::kem(sealed.kem)?
        .decapsulate(secret, &sealed.kem_ciphertext)
        .map_err(|_| Error::DecryptionFailed)?;
    let prefix = sealed.header_and_kem_ciphertext();
    let (key, nonce) = derive(&prefix, ss.expose());
    let cipher =
        ChaCha20Poly1305::new_from_slice(&*key).map_err(|_| Error::Backend("bad AEAD key"))?;
    cipher
        .decrypt(
            &Nonce::from(nonce),
            Payload {
                msg: &sealed.body,
                aad: &full_aad(&prefix, aad),
            },
        )
        .map_err(|_| Error::DecryptionFailed)
}
