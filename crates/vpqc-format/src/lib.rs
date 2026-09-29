//! Wire formats. Every object starts with the magic `VPQC`, a format version and an
//! object kind. Algorithm identifiers are inside the object and inside the data that is
//! authenticated, so an attacker cannot downgrade the algorithm without detection.
//!
//! ```text
//! sealed     : "VPQC" 01 01 kem_id:u16 aead_id:u8 ct_len:u16 | kem_ct | aead_body
//! signature  : "VPQC" 01 02 sig_id:u16 sig_len:u32           | signature
//! public key : "VPQC" 01 03 alg_id:u16 key_len:u32           | key | crc4
//! secret key : "VPQC" 01 04 alg_id:u16 key_len:u32           | key | crc4
//! stream     : "VPQC" 01 05 kem_id:u16 aead_id:u8 chunk_log:u8 ct_len:u16 | kem_ct | chunks  (ADR-0007)
//! multi      : "VPQC" 01 06 aead_id:u8 chunk_log:u8 n:u8 | n x stanza | mac | chunks      (ADR-0009)
//! ```
//! All integers are big-endian. `crc4` is the first four bytes of SHA3-256 over the
//! preceding bytes; it only catches typos and truncation and provides no security.

mod armor;
mod keys;
mod sealed;
mod signature;
mod stream;

pub use armor::{armor, dearmor};
pub use keys::{decode_public_key, decode_secret_key, encode_public_key, encode_secret_key};
pub use sealed::Sealed;
pub use signature::DetachedSignature;
pub use stream::{
    AnyStreamHeader, DEFAULT_CHUNK_LOG, HEADER_MAC_LEN, HeaderScan, MAX_CHUNK_LOG, MAX_RECIPIENTS,
    MIN_CHUNK_LOG, MultiStreamHeader, RecipientStanza, StreamHeader, WRAPPED_KEY_LEN,
};

pub(crate) const MAGIC: [u8; 4] = *b"VPQC";
pub(crate) const VERSION: u8 = 1;

/// Object kind byte.
pub(crate) mod kind {
    pub(crate) const SEALED: u8 = 1;
    pub(crate) const SIGNATURE: u8 = 2;
    pub(crate) const PUBLIC_KEY: u8 = 3;
    pub(crate) const SECRET_KEY: u8 = 4;
    pub(crate) const STREAM: u8 = 5;
    pub(crate) const MULTI_STREAM: u8 = 6;
}

/// Minimal cursor over a byte slice with strict bounds checking.
pub(crate) struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub(crate) fn take(&mut self, n: usize) -> vpqc_core::Result<&'a [u8]> {
        if self.data.len() < n {
            return Err(vpqc_core::Error::Format("truncated"));
        }
        let (head, tail) = self.data.split_at(n);
        self.data = tail;
        Ok(head)
    }

    pub(crate) fn u8(&mut self) -> vpqc_core::Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn u16(&mut self) -> vpqc_core::Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub(crate) fn u32(&mut self) -> vpqc_core::Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub(crate) fn rest(&mut self) -> &'a [u8] {
        std::mem::take(&mut self.data)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Check magic, version and kind.
    pub(crate) fn header(&mut self, kind: u8) -> vpqc_core::Result<()> {
        if self.take(4)? != MAGIC {
            return Err(vpqc_core::Error::Format("bad magic"));
        }
        if self.u8()? != VERSION {
            return Err(vpqc_core::Error::Format("unsupported version"));
        }
        if self.u8()? != kind {
            return Err(vpqc_core::Error::Format("unexpected object kind"));
        }
        Ok(())
    }
}
