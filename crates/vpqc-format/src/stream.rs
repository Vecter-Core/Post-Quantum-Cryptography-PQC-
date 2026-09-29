use std::io::Read;

use vpqc_core::{AeadId, Error, KemId, Result};

use crate::{MAGIC, Reader, VERSION, kind};

/// Smallest allowed chunk size exponent (1 KiB).
pub const MIN_CHUNK_LOG: u8 = 10;
/// Largest allowed chunk size exponent (16 MiB).
pub const MAX_CHUNK_LOG: u8 = 24;
/// Default chunk size exponent (64 KiB).
pub const DEFAULT_CHUNK_LOG: u8 = 16;

/// Header of a streaming ciphertext (ADR-0007).
///
/// ```text
/// "VPQC" 01 05 kem_id:u16 aead_id:u8 chunk_log:u8 ct_len:u16 | kem_ct
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamHeader {
    /// KEM used to derive the stream key.
    pub kem: KemId,
    /// AEAD protecting each chunk.
    pub aead: AeadId,
    /// Chunk size is `2^chunk_log` plaintext bytes.
    pub chunk_log: u8,
    /// KEM ciphertext.
    pub kem_ciphertext: Vec<u8>,
}

impl StreamHeader {
    /// Plaintext bytes per full chunk.
    pub fn chunk_size(&self) -> usize {
        1usize << self.chunk_log
    }

    /// Serialize. These exact bytes are bound into the stream key.
    pub fn encode(&self) -> Result<Vec<u8>> {
        check_chunk_log(self.chunk_log)?;
        let ct_len = u16::try_from(self.kem_ciphertext.len())
            .map_err(|_| Error::Format("KEM ciphertext too long"))?;
        let mut out = Vec::with_capacity(12 + self.kem_ciphertext.len());
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.push(kind::STREAM);
        out.extend_from_slice(&self.kem.to_u16().to_be_bytes());
        out.push(self.aead.to_u8());
        out.push(self.chunk_log);
        out.extend_from_slice(&ct_len.to_be_bytes());
        out.extend_from_slice(&self.kem_ciphertext);
        Ok(out)
    }

    /// Read a header from the start of `input`, consuming exactly the header bytes.
    /// Returns the header and its raw encoding.
    pub fn read_from<R: Read + ?Sized>(input: &mut R) -> std::io::Result<(Self, Vec<u8>)> {
        let invalid = |e: Error| std::io::Error::new(std::io::ErrorKind::InvalidData, e);
        let mut fixed = [0u8; 12];
        input.read_exact(&mut fixed).map_err(|e| match e.kind() {
            std::io::ErrorKind::UnexpectedEof => invalid(Error::Format("truncated")),
            _ => e,
        })?;
        let mut r = Reader::new(&fixed);
        r.header(kind::STREAM).map_err(invalid)?;
        let kem = KemId::from_u16(r.u16().map_err(invalid)?).map_err(invalid)?;
        let aead = AeadId::from_u8(r.u8().map_err(invalid)?).map_err(invalid)?;
        let chunk_log = r.u8().map_err(invalid)?;
        check_chunk_log(chunk_log).map_err(invalid)?;
        let ct_len = r.u16().map_err(invalid)? as usize;
        let mut kem_ciphertext = vec![0u8; ct_len];
        input
            .read_exact(&mut kem_ciphertext)
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::UnexpectedEof => invalid(Error::Format("truncated")),
                _ => e,
            })?;
        let header = StreamHeader {
            kem,
            aead,
            chunk_log,
            kem_ciphertext,
        };
        let raw = header.encode().map_err(invalid)?;
        Ok((header, raw))
    }

    /// Parse a header from the beginning of a byte slice (for `inspect`).
    pub fn decode_prefix(bytes: &[u8]) -> Result<Self> {
        let mut cursor = bytes;
        Self::read_from(&mut cursor)
            .map(|(h, _)| h)
            .map_err(|_| Error::Format("not a stream header"))
    }
}

fn check_chunk_log(chunk_log: u8) -> Result<()> {
    if (MIN_CHUNK_LOG..=MAX_CHUNK_LOG).contains(&chunk_log) {
        Ok(())
    } else {
        Err(Error::Format("chunk size out of range"))
    }
}
