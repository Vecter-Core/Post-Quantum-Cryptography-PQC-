use crate::{Error, KemId, Result, SigId};

/// A named, vetted combination of algorithms. Users pick a profile, not algorithms.
///
/// Rationale for each choice is in `docs/ROADMAP.md` (section 1 and 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Profile {
    /// Default. Hybrid KEM (X25519 + ML-KEM-768) and composite signature
    /// (Ed25519 + ML-DSA-65).
    Standard,
    /// Hybrid KEM, classical Ed25519 signatures. For short-lived authentication where a
    /// forged signature is only useful *while* the session lives, so a quantum
    /// adversary arrives too late. **Not** for certificates, firmware or archives.
    FastAuth,
    /// CNSA 2.0 style: ML-KEM-1024 and ML-DSA-87, no classical component.
    Cnsa2,
    /// Long-lived data: hybrid P-384 + ML-KEM-1024 KEM and composite ECDSA-P384 + ML-DSA-87
    /// signatures. Larger keys and signatures than `Standard`, higher security category.
    High,
}

impl Profile {
    /// All profiles.
    pub const ALL: [Profile; 4] = [
        Profile::Standard,
        Profile::FastAuth,
        Profile::Cnsa2,
        Profile::High,
    ];

    /// The KEM used for encryption under this profile.
    pub const fn kem(self) -> KemId {
        match self {
            Profile::Standard | Profile::FastAuth => KemId::XWing,
            Profile::Cnsa2 => KemId::MlKem1024,
            Profile::High => KemId::MlKem1024P384,
        }
    }

    /// The signature scheme used under this profile.
    pub const fn signature(self) -> SigId {
        match self {
            Profile::Standard => SigId::Ed25519MlDsa65,
            Profile::FastAuth => SigId::Ed25519,
            Profile::Cnsa2 => SigId::MlDsa87,
            Profile::High => SigId::EcdsaP384MlDsa87,
        }
    }

    /// Wire value.
    pub const fn to_u8(self) -> u8 {
        match self {
            Profile::Standard => 1,
            Profile::FastAuth => 2,
            Profile::Cnsa2 => 3,
            Profile::High => 4,
        }
    }

    /// Parse a wire value.
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            1 => Ok(Profile::Standard),
            2 => Ok(Profile::FastAuth),
            3 => Ok(Profile::Cnsa2),
            4 => Ok(Profile::High),
            _ => Err(Error::Unsupported("unknown profile id")),
        }
    }

    /// Canonical lowercase name.
    pub const fn name(self) -> &'static str {
        match self {
            Profile::Standard => "standard",
            Profile::FastAuth => "fast-auth",
            Profile::Cnsa2 => "cnsa2",
            Profile::High => "high",
        }
    }

    /// Parse a canonical name.
    pub fn from_name(name: &str) -> Result<Self> {
        Profile::ALL
            .into_iter()
            .find(|p| p.name() == name)
            .ok_or(Error::Unsupported("unknown profile name"))
    }
}
