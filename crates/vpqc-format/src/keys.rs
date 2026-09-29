use sha3::{Digest, Sha3_256};
use vpqc_core::{AlgorithmId, Error, PublicKey, Result, SecretKey};

use crate::{MAGIC, Reader, VERSION, kind};

fn encode(kind: u8, alg: AlgorithmId, key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 1 + 1 + 2 + 4 + key.len() + 4);
    out.extend_from_slice(&MAGIC);
    out.push(VERSION);
    out.push(kind);
    out.extend_from_slice(&alg.to_u16().to_be_bytes());
    out.extend_from_slice(&(key.len() as u32).to_be_bytes());
    out.extend_from_slice(key);
    let crc = Sha3_256::digest(&out);
    out.extend_from_slice(&crc[..4]);
    out
}

fn decode(kind: u8, bytes: &[u8]) -> Result<(AlgorithmId, Vec<u8>)> {
    if bytes.len() < 4 {
        return Err(Error::Format("truncated"));
    }
    let (body, crc) = bytes.split_at(bytes.len() - 4);
    if Sha3_256::digest(body)[..4] != *crc {
        return Err(Error::Format("checksum mismatch"));
    }
    let mut r = Reader::new(body);
    r.header(kind)?;
    let alg = AlgorithmId::from_u16(r.u16()?)?;
    let len = r.u32()? as usize;
    let key = r.take(len)?;
    if !r.is_empty() {
        return Err(Error::Format("trailing data"));
    }
    Ok((alg, key.to_vec()))
}

/// Serialize a public key.
pub fn encode_public_key(key: &PublicKey) -> Vec<u8> {
    encode(kind::PUBLIC_KEY, key.algorithm(), key.as_bytes())
}

/// Parse a public key.
pub fn decode_public_key(bytes: &[u8]) -> Result<PublicKey> {
    decode(kind::PUBLIC_KEY, bytes).map(|(alg, k)| PublicKey::new(alg, k))
}

/// Serialize a secret key (seed). The output is **unencrypted**; protect it.
pub fn encode_secret_key(key: &SecretKey) -> Vec<u8> {
    encode(kind::SECRET_KEY, key.algorithm(), key.expose_bytes())
}

/// Parse a secret key.
pub fn decode_secret_key(bytes: &[u8]) -> Result<SecretKey> {
    decode(kind::SECRET_KEY, bytes).map(|(alg, k)| SecretKey::new(alg, k))
}
