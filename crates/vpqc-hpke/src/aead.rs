//! HPKE AEADs.

use aes_gcm::aead::{Aead as _, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;
use vpqc_core::{Error, Result};

/// HPKE AEAD identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Aead {
    /// AES-128-GCM (`0x0001`).
    Aes128Gcm,
    /// AES-256-GCM (`0x0002`).
    Aes256Gcm,
    /// ChaCha20-Poly1305 (`0x0003`).
    ChaCha20Poly1305,
    /// Export-only (`0xFFFF`): no encryption, only [`crate::Context::export`].
    ExportOnly,
}

impl Aead {
    /// IANA identifier.
    pub const fn id(self) -> u16 {
        match self {
            Aead::Aes128Gcm => 0x0001,
            Aead::Aes256Gcm => 0x0002,
            Aead::ChaCha20Poly1305 => 0x0003,
            Aead::ExportOnly => 0xffff,
        }
    }

    /// Parse an IANA identifier.
    pub fn from_id(id: u16) -> Result<Self> {
        Ok(match id {
            0x0001 => Aead::Aes128Gcm,
            0x0002 => Aead::Aes256Gcm,
            0x0003 => Aead::ChaCha20Poly1305,
            0xffff => Aead::ExportOnly,
            _ => return Err(Error::Unsupported("HPKE AEAD")),
        })
    }

    /// Key length `Nk`.
    pub const fn nk(self) -> usize {
        match self {
            Aead::Aes128Gcm => 16,
            Aead::Aes256Gcm | Aead::ChaCha20Poly1305 => 32,
            Aead::ExportOnly => 0,
        }
    }

    /// Nonce length `Nn`.
    pub const fn nn(self) -> usize {
        match self {
            Aead::ExportOnly => 0,
            _ => 12,
        }
    }

    pub(crate) fn seal(self, key: &[u8], nonce: &[u8], aad: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
        let payload = Payload { msg: pt, aad };
        let fail = |_| Error::Backend("AEAD encryption failed");
        let bad_key = |_| Error::Backend("bad AEAD key");
        match self {
            Aead::Aes128Gcm => Aes128Gcm::new_from_slice(key)
                .map_err(bad_key)?
                .encrypt(
                    nonce.try_into().map_err(|_| Error::Backend("nonce"))?,
                    payload,
                )
                .map_err(fail),
            Aead::Aes256Gcm => Aes256Gcm::new_from_slice(key)
                .map_err(bad_key)?
                .encrypt(
                    nonce.try_into().map_err(|_| Error::Backend("nonce"))?,
                    payload,
                )
                .map_err(fail),
            Aead::ChaCha20Poly1305 => ChaCha20Poly1305::new_from_slice(key)
                .map_err(bad_key)?
                .encrypt(
                    nonce.try_into().map_err(|_| Error::Backend("nonce"))?,
                    payload,
                )
                .map_err(fail),
            Aead::ExportOnly => Err(Error::Unsupported("export-only suite cannot encrypt")),
        }
    }

    pub(crate) fn open(self, key: &[u8], nonce: &[u8], aad: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
        let payload = Payload { msg: ct, aad };
        let fail = |_| Error::DecryptionFailed;
        let bad_key = |_| Error::Backend("bad AEAD key");
        match self {
            Aead::Aes128Gcm => Aes128Gcm::new_from_slice(key)
                .map_err(bad_key)?
                .decrypt(
                    nonce.try_into().map_err(|_| Error::Backend("nonce"))?,
                    payload,
                )
                .map_err(fail),
            Aead::Aes256Gcm => Aes256Gcm::new_from_slice(key)
                .map_err(bad_key)?
                .decrypt(
                    nonce.try_into().map_err(|_| Error::Backend("nonce"))?,
                    payload,
                )
                .map_err(fail),
            Aead::ChaCha20Poly1305 => ChaCha20Poly1305::new_from_slice(key)
                .map_err(bad_key)?
                .decrypt(
                    nonce.try_into().map_err(|_| Error::Backend("nonce"))?,
                    payload,
                )
                .map_err(fail),
            Aead::ExportOnly => Err(Error::Unsupported("export-only suite cannot decrypt")),
        }
    }
}
