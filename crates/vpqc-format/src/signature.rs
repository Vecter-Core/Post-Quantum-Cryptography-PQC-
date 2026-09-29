use vpqc_core::{Result, SigId};

use crate::{MAGIC, Reader, VERSION, kind};

/// A detached signature tagged with its algorithm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetachedSignature {
    /// Algorithm that produced the signature.
    pub algorithm: SigId,
    /// Raw signature bytes.
    pub bytes: Vec<u8>,
}

impl DetachedSignature {
    /// Serialize.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(12 + self.bytes.len());
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.push(kind::SIGNATURE);
        out.extend_from_slice(&self.algorithm.to_u16().to_be_bytes());
        out.extend_from_slice(&(self.bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.bytes);
        out
    }

    /// Parse.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        r.header(kind::SIGNATURE)?;
        let algorithm = SigId::from_u16(r.u16()?)?;
        let len = r.u32()? as usize;
        let sig = r.take(len)?.to_vec();
        if !r.is_empty() {
            return Err(vpqc_core::Error::Format("trailing data"));
        }
        Ok(Self {
            algorithm,
            bytes: sig,
        })
    }
}
