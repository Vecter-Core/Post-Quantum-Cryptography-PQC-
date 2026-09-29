use vpqc_core::{AeadId, Error, KemId, Result};

use crate::{MAGIC, Reader, VERSION, kind};

/// A sealed-box envelope: a KEM ciphertext followed by an AEAD body.
///
/// [`Sealed::header_and_kem_ciphertext`] is what the AEAD authenticates and what the KDF
/// binds, so tampering with the algorithm identifiers or the KEM ciphertext is detected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    /// KEM used to derive the key.
    pub kem: KemId,
    /// AEAD protecting the payload.
    pub aead: AeadId,
    /// KEM ciphertext.
    pub kem_ciphertext: Vec<u8>,
    /// AEAD ciphertext including the authentication tag.
    pub body: Vec<u8>,
}

impl Sealed {
    /// The authenticated prefix: header fields plus the KEM ciphertext.
    pub fn header_and_kem_ciphertext(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(11 + self.kem_ciphertext.len());
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.push(kind::SEALED);
        out.extend_from_slice(&self.kem.to_u16().to_be_bytes());
        out.push(self.aead.to_u8());
        out.extend_from_slice(&(self.kem_ciphertext.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.kem_ciphertext);
        out
    }

    /// Serialize.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.header_and_kem_ciphertext();
        out.extend_from_slice(&self.body);
        out
    }

    /// Parse. Structure is validated here; authenticity is checked when opening.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        r.header(kind::SEALED)?;
        let kem = KemId::from_u16(r.u16()?)?;
        let aead = AeadId::from_u8(r.u8()?)?;
        let ct_len = r.u16()? as usize;
        let kem_ciphertext = r.take(ct_len)?.to_vec();
        let body = r.rest().to_vec();
        if body.len() < 16 {
            return Err(Error::Format("body shorter than an authentication tag"));
        }
        Ok(Self {
            kem,
            aead,
            kem_ciphertext,
            body,
        })
    }
}
