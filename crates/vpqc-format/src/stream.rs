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

/// Most recipients in a multi-recipient stream.
pub const MAX_RECIPIENTS: usize = 32;
/// The file key wrapped for one recipient: 32-byte key + 16-byte tag.
pub const WRAPPED_KEY_LEN: usize = 48;
/// Length of the header MAC.
pub const HEADER_MAC_LEN: usize = 32;
/// KEM ciphertexts longer than this are rejected while parsing (the largest vpqc KEM
/// ciphertext is 1665 bytes).
const MAX_KEM_CIPHERTEXT: usize = 4096;

/// The file key wrapped for one recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientStanza {
    /// The recipient's KEM.
    pub kem: KemId,
    /// KEM ciphertext.
    pub kem_ciphertext: Vec<u8>,
    /// The file key encrypted under a key derived from the KEM shared secret.
    pub wrapped_key: [u8; WRAPPED_KEY_LEN],
}

/// Header of a multi-recipient stream (ADR-0009).
///
/// ```text
/// "VPQC" 01 06 aead_id:u8 chunk_log:u8 n:u8
///   n x (kem_id:u16 ct_len:u16 | kem_ct | wrapped_key[48])
///   header_mac[32]
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiStreamHeader {
    /// AEAD protecting each chunk.
    pub aead: AeadId,
    /// Chunk size is `2^chunk_log` plaintext bytes.
    pub chunk_log: u8,
    /// One stanza per recipient (1..=[`MAX_RECIPIENTS`]).
    pub recipients: Vec<RecipientStanza>,
    /// MAC over everything before it, keyed with the file key.
    pub mac: [u8; HEADER_MAC_LEN],
}

impl MultiStreamHeader {
    /// Plaintext bytes per full chunk.
    pub fn chunk_size(&self) -> usize {
        1usize << self.chunk_log
    }

    /// The bytes covered by the header MAC (everything except the MAC itself).
    pub fn encode_unauthenticated(&self) -> Result<Vec<u8>> {
        check_chunk_log(self.chunk_log)?;
        if self.recipients.is_empty() || self.recipients.len() > MAX_RECIPIENTS {
            return Err(Error::Format("recipient count out of range"));
        }
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.push(kind::MULTI_STREAM);
        out.push(self.aead.to_u8());
        out.push(self.chunk_log);
        out.push(self.recipients.len() as u8);
        for r in &self.recipients {
            if r.kem_ciphertext.len() > MAX_KEM_CIPHERTEXT {
                return Err(Error::Format("KEM ciphertext too long"));
            }
            out.extend_from_slice(&r.kem.to_u16().to_be_bytes());
            out.extend_from_slice(&(r.kem_ciphertext.len() as u16).to_be_bytes());
            out.extend_from_slice(&r.kem_ciphertext);
            out.extend_from_slice(&r.wrapped_key);
        }
        Ok(out)
    }

    /// Serialize, MAC included. These exact bytes are bound into the stream key.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = self.encode_unauthenticated()?;
        out.extend_from_slice(&self.mac);
        Ok(out)
    }

    fn parse(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        r.header(kind::MULTI_STREAM)?;
        let aead = AeadId::from_u8(r.u8()?)?;
        let chunk_log = r.u8()?;
        check_chunk_log(chunk_log)?;
        let n = r.u8()? as usize;
        if n == 0 || n > MAX_RECIPIENTS {
            return Err(Error::Format("recipient count out of range"));
        }
        let mut recipients = Vec::with_capacity(n);
        for _ in 0..n {
            let kem = KemId::from_u16(r.u16()?)?;
            let ct_len = r.u16()? as usize;
            let kem_ciphertext = r.take(ct_len)?.to_vec();
            let wrapped_key = r.take(WRAPPED_KEY_LEN)?.try_into().expect("length checked");
            recipients.push(RecipientStanza {
                kem,
                kem_ciphertext,
                wrapped_key,
            });
        }
        let mac = r.take(HEADER_MAC_LEN)?.try_into().expect("length checked");
        if !r.is_empty() {
            return Err(Error::Format("trailing bytes in header"));
        }
        Ok(Self {
            aead,
            chunk_log,
            recipients,
            mac,
        })
    }
}

/// A stream header of either kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnyStreamHeader {
    /// Single-recipient stream (kind 5, ADR-0007).
    Single(StreamHeader),
    /// Multi-recipient stream (kind 6, ADR-0009).
    Multi(MultiStreamHeader),
}

/// How much of a stream header a prefix contains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderScan {
    /// The header is exactly this many bytes long, and the prefix contains it.
    Complete(usize),
    /// The prefix is too short; at least this many bytes in total are needed.
    NeedAtLeast(usize),
}

impl AnyStreamHeader {
    /// Plaintext bytes per full chunk.
    pub fn chunk_size(&self) -> usize {
        match self {
            AnyStreamHeader::Single(h) => h.chunk_size(),
            AnyStreamHeader::Multi(h) => h.chunk_size(),
        }
    }

    /// Determine the header length from a prefix of the stream, without reading past it.
    /// Fails as soon as the prefix shows it is not a valid stream header.
    pub fn scan(prefix: &[u8]) -> Result<HeaderScan> {
        let need = |n: usize| -> Option<HeaderScan> {
            (prefix.len() < n).then_some(HeaderScan::NeedAtLeast(n))
        };
        if let Some(s) = need(6) {
            if prefix.len() >= 4 && prefix[..4] != MAGIC {
                return Err(Error::Format("bad magic"));
            }
            return Ok(s);
        }
        if prefix[..4] != MAGIC {
            return Err(Error::Format("bad magic"));
        }
        if prefix[4] != VERSION {
            return Err(Error::Format("unsupported version"));
        }
        let len = match prefix[5] {
            kind::STREAM => {
                if let Some(s) = need(12) {
                    return Ok(s);
                }
                12 + u16::from_be_bytes([prefix[10], prefix[11]]) as usize
            }
            kind::MULTI_STREAM => {
                if let Some(s) = need(9) {
                    return Ok(s);
                }
                let n = prefix[8] as usize;
                if n == 0 || n > MAX_RECIPIENTS {
                    return Err(Error::Format("recipient count out of range"));
                }
                let mut pos = 9;
                for _ in 0..n {
                    if let Some(s) = need(pos + 4) {
                        return Ok(s);
                    }
                    let ct_len = u16::from_be_bytes([prefix[pos + 2], prefix[pos + 3]]) as usize;
                    if ct_len > MAX_KEM_CIPHERTEXT {
                        return Err(Error::Format("KEM ciphertext too long"));
                    }
                    pos += 4 + ct_len + WRAPPED_KEY_LEN;
                }
                pos + HEADER_MAC_LEN
            }
            _ => return Err(Error::Format("not a stream")),
        };
        Ok(need(len).unwrap_or(HeaderScan::Complete(len)))
    }

    /// Parse exactly one complete header (as measured by [`AnyStreamHeader::scan`]).
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        match bytes.get(5) {
            Some(&kind::STREAM) => {
                let mut cursor = bytes;
                let (h, raw) = StreamHeader::read_from(&mut cursor)
                    .map_err(|_| Error::Format("bad stream header"))?;
                if raw.len() != bytes.len() {
                    return Err(Error::Format("trailing bytes in header"));
                }
                Ok(AnyStreamHeader::Single(h))
            }
            Some(&kind::MULTI_STREAM) => {
                MultiStreamHeader::parse(bytes).map(AnyStreamHeader::Multi)
            }
            _ => Err(Error::Format("not a stream")),
        }
    }

    /// Read a header of either kind from the start of `input`, consuming exactly its bytes.
    /// Returns the header and its raw encoding.
    pub fn read_from<R: Read + ?Sized>(input: &mut R) -> std::io::Result<(Self, Vec<u8>)> {
        let invalid = |e: Error| std::io::Error::new(std::io::ErrorKind::InvalidData, e);
        let mut buf = Vec::new();
        loop {
            match Self::scan(&buf).map_err(invalid)? {
                HeaderScan::Complete(n) => {
                    debug_assert_eq!(n, buf.len());
                    return Ok((Self::parse(&buf).map_err(invalid)?, buf));
                }
                HeaderScan::NeedAtLeast(n) => {
                    let start = buf.len();
                    buf.resize(n, 0);
                    input
                        .read_exact(&mut buf[start..])
                        .map_err(|e| match e.kind() {
                            std::io::ErrorKind::UnexpectedEof => {
                                invalid(Error::Format("truncated"))
                            }
                            _ => e,
                        })?;
                }
            }
        }
    }

    /// Parse a header from the beginning of a byte slice (for `inspect`).
    pub fn decode_prefix(bytes: &[u8]) -> Result<Self> {
        let mut cursor = bytes;
        Self::read_from(&mut cursor)
            .map(|(h, _)| h)
            .map_err(|_| Error::Format("not a stream header"))
    }
}
