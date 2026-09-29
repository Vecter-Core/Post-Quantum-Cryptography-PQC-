use vpqc_backend_libcrux::{MlDsa65, MlDsa87, MlKem768, MlKem1024};
use vpqc_core::{Error, Kem, KemId, Result, SigId, SignatureScheme};
use vpqc_hybrid::{CompositeEd25519MlDsa65, Ed25519, XWing};

/// The implementation of a KEM.
pub fn kem(id: KemId) -> Result<&'static dyn Kem> {
    Ok(match id {
        KemId::XWing => &XWing,
        KemId::MlKem768 => &MlKem768,
        KemId::MlKem1024 => &MlKem1024,
        _ => return Err(Error::Unsupported("KEM not compiled in")),
    })
}

/// The implementation of a signature scheme.
pub fn signature_scheme(id: SigId) -> Result<&'static dyn SignatureScheme> {
    Ok(match id {
        SigId::Ed25519 => &Ed25519,
        SigId::MlDsa65 => &MlDsa65,
        SigId::MlDsa87 => &MlDsa87,
        SigId::Ed25519MlDsa65 => &CompositeEd25519MlDsa65,
        _ => return Err(Error::Unsupported("signature scheme not compiled in")),
    })
}
