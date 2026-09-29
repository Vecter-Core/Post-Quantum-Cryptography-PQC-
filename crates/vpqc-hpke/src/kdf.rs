//! HPKE KDFs: two-stage (HKDF) and single-stage (SHAKE).

use hkdf::Hkdf;
use sha2::{Sha256, Sha384, Sha512};
use vpqc_core::{Error, Result};

/// HPKE KDF identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kdf {
    /// HKDF-SHA256 (`0x0001`).
    HkdfSha256,
    /// HKDF-SHA384 (`0x0002`).
    HkdfSha384,
    /// HKDF-SHA512 (`0x0003`).
    HkdfSha512,
    /// SHAKE128 single-stage KDF (`0x0010`).
    Shake128,
    /// SHAKE256 single-stage KDF (`0x0011`).
    Shake256,
}

const VERSION: &[u8] = b"HPKE-v1";

impl Kdf {
    /// IANA identifier.
    pub const fn id(self) -> u16 {
        match self {
            Kdf::HkdfSha256 => 0x0001,
            Kdf::HkdfSha384 => 0x0002,
            Kdf::HkdfSha512 => 0x0003,
            Kdf::Shake128 => 0x0010,
            Kdf::Shake256 => 0x0011,
        }
    }

    /// Parse an IANA identifier.
    pub fn from_id(id: u16) -> Result<Self> {
        Ok(match id {
            0x0001 => Kdf::HkdfSha256,
            0x0002 => Kdf::HkdfSha384,
            0x0003 => Kdf::HkdfSha512,
            0x0010 => Kdf::Shake128,
            0x0011 => Kdf::Shake256,
            _ => return Err(Error::Unsupported("HPKE KDF")),
        })
    }

    /// Output size `Nh`.
    pub const fn nh(self) -> usize {
        match self {
            Kdf::HkdfSha256 | Kdf::Shake128 => 32,
            Kdf::HkdfSha384 => 48,
            Kdf::HkdfSha512 | Kdf::Shake256 => 64,
        }
    }

    /// Whether this is an Extract/Expand KDF.
    pub const fn is_two_stage(self) -> bool {
        matches!(self, Kdf::HkdfSha256 | Kdf::HkdfSha384 | Kdf::HkdfSha512)
    }

    /// `LabeledExtract(salt, label, ikm)` (two-stage KDFs).
    pub(crate) fn labeled_extract(
        self,
        suite_id: &[u8],
        salt: &[u8],
        label: &[u8],
        ikm: &[u8],
    ) -> Result<Vec<u8>> {
        let mut labeled = zeroize::Zeroizing::new(Vec::with_capacity(
            VERSION.len() + suite_id.len() + label.len() + ikm.len(),
        ));
        labeled.extend_from_slice(VERSION);
        labeled.extend_from_slice(suite_id);
        labeled.extend_from_slice(label);
        labeled.extend_from_slice(ikm);
        Ok(match self {
            Kdf::HkdfSha256 => Hkdf::<Sha256>::extract(Some(salt), &labeled).0.to_vec(),
            Kdf::HkdfSha384 => Hkdf::<Sha384>::extract(Some(salt), &labeled).0.to_vec(),
            Kdf::HkdfSha512 => Hkdf::<Sha512>::extract(Some(salt), &labeled).0.to_vec(),
            _ => return Err(Error::Unsupported("Extract on a single-stage KDF")),
        })
    }

    /// `LabeledExpand(prk, label, info, L)` (two-stage KDFs), `L <= 255 * Nh`.
    pub(crate) fn labeled_expand(
        self,
        suite_id: &[u8],
        prk: &[u8],
        label: &[u8],
        info: &[u8],
        len: usize,
    ) -> Result<Vec<u8>> {
        if len > 255 * self.nh() {
            return Err(Error::Format("HPKE output length too large"));
        }
        let mut labeled =
            Vec::with_capacity(2 + VERSION.len() + suite_id.len() + label.len() + info.len());
        labeled.extend_from_slice(&crate::len16(len)?);
        labeled.extend_from_slice(VERSION);
        labeled.extend_from_slice(suite_id);
        labeled.extend_from_slice(label);
        labeled.extend_from_slice(info);
        let mut out = vec![0u8; len];
        let bad = |_| Error::Backend("HKDF expand failed");
        match self {
            Kdf::HkdfSha256 => Hkdf::<Sha256>::from_prk(prk)
                .map_err(|_| Error::Backend("bad PRK"))?
                .expand(&labeled, &mut out)
                .map_err(bad)?,
            Kdf::HkdfSha384 => Hkdf::<Sha384>::from_prk(prk)
                .map_err(|_| Error::Backend("bad PRK"))?
                .expand(&labeled, &mut out)
                .map_err(bad)?,
            Kdf::HkdfSha512 => Hkdf::<Sha512>::from_prk(prk)
                .map_err(|_| Error::Backend("bad PRK"))?
                .expand(&labeled, &mut out)
                .map_err(bad)?,
            _ => return Err(Error::Unsupported("Expand on a single-stage KDF")),
        }
        Ok(out)
    }

    /// `LabeledDerive(ikm, label, context, L)` (single-stage KDFs), `L < 2^16`.
    pub(crate) fn labeled_derive(
        self,
        suite_id: &[u8],
        ikm: &[u8],
        label: &[u8],
        context: &[u8],
        len: usize,
    ) -> Result<Vec<u8>> {
        let mut labeled = zeroize::Zeroizing::new(Vec::with_capacity(
            ikm.len() + VERSION.len() + suite_id.len() + 4 + label.len() + context.len(),
        ));
        labeled.extend_from_slice(ikm);
        labeled.extend_from_slice(VERSION);
        labeled.extend_from_slice(suite_id);
        labeled.extend_from_slice(&crate::length_prefixed(label)?);
        labeled.extend_from_slice(&crate::len16(len)?);
        labeled.extend_from_slice(context);
        let mut out = vec![0u8; len];
        match self {
            Kdf::Shake128 => libcrux_sha3::shake128_ema(&mut out, &labeled),
            Kdf::Shake256 => libcrux_sha3::shake256_ema(&mut out, &labeled),
            _ => return Err(Error::Unsupported("Derive on a two-stage KDF")),
        }
        Ok(out)
    }
}
