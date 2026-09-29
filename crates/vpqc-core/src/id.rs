use crate::{Error, Result};

/// Key-encapsulation algorithm identifiers (vpqc registry, big-endian `u16` on the wire).
///
/// These are vpqc-private numbers. They will be mapped to the IANA HPKE/TLS registries
/// where a standard code point exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KemId {
    /// X-Wing: X25519 + ML-KEM-768 (draft-connolly-cfrg-xwing-kem).
    XWing,
    /// ML-KEM-768 alone (FIPS 203).
    MlKem768,
    /// ML-KEM-1024 alone (FIPS 203).
    MlKem1024,
    /// MLKEM1024-P384: ML-KEM-1024 + NIST P-384 (draft-irtf-cfrg-concrete-hybrid-kems).
    MlKem1024P384,
}

impl KemId {
    /// Wire value.
    pub const fn to_u16(self) -> u16 {
        match self {
            KemId::XWing => 0x0001,
            KemId::MlKem768 => 0x0002,
            KemId::MlKem1024 => 0x0003,
            KemId::MlKem1024P384 => 0x0004,
        }
    }

    /// Parse a wire value.
    pub fn from_u16(v: u16) -> Result<Self> {
        match v {
            0x0001 => Ok(KemId::XWing),
            0x0002 => Ok(KemId::MlKem768),
            0x0003 => Ok(KemId::MlKem1024),
            0x0004 => Ok(KemId::MlKem1024P384),
            _ => Err(Error::Unsupported("unknown KEM id")),
        }
    }

    /// Human-readable name.
    pub const fn name(self) -> &'static str {
        match self {
            KemId::XWing => "X-Wing (X25519+ML-KEM-768)",
            KemId::MlKem768 => "ML-KEM-768",
            KemId::MlKem1024 => "ML-KEM-1024",
            KemId::MlKem1024P384 => "MLKEM1024-P384 (P-384+ML-KEM-1024)",
        }
    }

    /// Whether the KEM combines a classical and a post-quantum component.
    pub const fn is_hybrid(self) -> bool {
        matches!(self, KemId::XWing | KemId::MlKem1024P384)
    }
}

/// Signature algorithm identifiers (vpqc registry, big-endian `u16` on the wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SigId {
    /// Ed25519 alone (classical; only for short-lived authentication).
    Ed25519,
    /// ML-DSA-65 alone (FIPS 204).
    MlDsa65,
    /// ML-DSA-87 alone (FIPS 204).
    MlDsa87,
    /// Composite Ed25519 + ML-DSA-65: both signatures must verify.
    Ed25519MlDsa65,
    /// Composite ECDSA-P384 + ML-DSA-87: both signatures must verify.
    EcdsaP384MlDsa87,
}

impl SigId {
    /// Wire value.
    pub const fn to_u16(self) -> u16 {
        match self {
            SigId::Ed25519 => 0x0101,
            SigId::MlDsa65 => 0x0102,
            SigId::MlDsa87 => 0x0103,
            SigId::Ed25519MlDsa65 => 0x0104,
            SigId::EcdsaP384MlDsa87 => 0x0105,
        }
    }

    /// Parse a wire value.
    pub fn from_u16(v: u16) -> Result<Self> {
        match v {
            0x0101 => Ok(SigId::Ed25519),
            0x0102 => Ok(SigId::MlDsa65),
            0x0103 => Ok(SigId::MlDsa87),
            0x0104 => Ok(SigId::Ed25519MlDsa65),
            0x0105 => Ok(SigId::EcdsaP384MlDsa87),
            _ => Err(Error::Unsupported("unknown signature id")),
        }
    }

    /// Human-readable name.
    pub const fn name(self) -> &'static str {
        match self {
            SigId::Ed25519 => "Ed25519",
            SigId::MlDsa65 => "ML-DSA-65",
            SigId::MlDsa87 => "ML-DSA-87",
            SigId::Ed25519MlDsa65 => "Ed25519+ML-DSA-65 (composite)",
            SigId::EcdsaP384MlDsa87 => "ECDSA-P384+ML-DSA-87 (composite)",
        }
    }

    /// Whether the signature is resistant to quantum attackers.
    pub const fn is_post_quantum(self) -> bool {
        !matches!(self, SigId::Ed25519)
    }
}

/// AEAD identifiers used by the sealed-box envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AeadId {
    /// ChaCha20-Poly1305 (RFC 8439), 256-bit key.
    ChaCha20Poly1305,
}

impl AeadId {
    /// Wire value.
    pub const fn to_u8(self) -> u8 {
        match self {
            AeadId::ChaCha20Poly1305 => 1,
        }
    }

    /// Parse a wire value.
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            1 => Ok(AeadId::ChaCha20Poly1305),
            _ => Err(Error::Unsupported("unknown AEAD id")),
        }
    }
}

/// An algorithm a key belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlgorithmId {
    /// A KEM key.
    Kem(KemId),
    /// A signature key.
    Sig(SigId),
}

impl AlgorithmId {
    /// Wire value (KEM and signature ranges do not overlap).
    pub const fn to_u16(self) -> u16 {
        match self {
            AlgorithmId::Kem(k) => k.to_u16(),
            AlgorithmId::Sig(s) => s.to_u16(),
        }
    }

    /// Parse a wire value.
    pub fn from_u16(v: u16) -> Result<Self> {
        match v >> 8 {
            0x00 => KemId::from_u16(v).map(AlgorithmId::Kem),
            0x01 => SigId::from_u16(v).map(AlgorithmId::Sig),
            _ => Err(Error::Unsupported("unknown algorithm id")),
        }
    }

    /// Human-readable name.
    pub const fn name(self) -> &'static str {
        match self {
            AlgorithmId::Kem(k) => k.name(),
            AlgorithmId::Sig(s) => s.name(),
        }
    }
}
