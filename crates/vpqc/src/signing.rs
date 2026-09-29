//! Digital signatures with mandatory domain-separation context.
//!
//! The `context` (at most 255 bytes) binds a signature to one purpose, e.g.
//! `b"my-app/release-v1"`. A signature made under one context never verifies under
//! another, which prevents cross-protocol signature reuse.

use vpqc_core::{AlgorithmId, Error, OsRng, Profile, PublicKey, RandomSource, Result, SecretKey};
use vpqc_format::DetachedSignature;

use crate::{KeyPair, registry};

/// Generate a signing key pair for `profile`.
pub fn generate(profile: Profile) -> Result<KeyPair> {
    generate_with(profile, &mut OsRng)
}

/// [`generate`] with an explicit randomness source (for tests).
pub fn generate_with(profile: Profile, rng: &mut dyn RandomSource) -> Result<KeyPair> {
    let (public, secret) = registry::signature_scheme(profile.signature())?.generate(rng)?;
    Ok(KeyPair { public, secret })
}

/// Sign `message` under `context`. Returns an encoded detached signature.
pub fn sign(secret: &SecretKey, message: &[u8], context: &[u8]) -> Result<Vec<u8>> {
    sign_with(secret, message, context, &mut OsRng)
}

/// [`sign`] with an explicit randomness source (for tests).
pub fn sign_with(
    secret: &SecretKey,
    message: &[u8],
    context: &[u8],
    rng: &mut dyn RandomSource,
) -> Result<Vec<u8>> {
    let AlgorithmId::Sig(id) = secret.algorithm() else {
        return Err(Error::AlgorithmMismatch);
    };
    let bytes = registry::signature_scheme(id)?.sign(secret, message, context, rng)?;
    Ok(DetachedSignature {
        algorithm: id,
        bytes,
    }
    .encode())
}

/// Verify a detached signature. Returns [`Error::VerificationFailed`] on any mismatch.
pub fn verify(public: &PublicKey, message: &[u8], context: &[u8], signature: &[u8]) -> Result<()> {
    let sig = DetachedSignature::decode(signature).map_err(|_| Error::VerificationFailed)?;
    // The verifier's key decides the algorithm. A signature that claims another one is
    // rejected, so an attacker cannot steer verification to a weaker scheme.
    if public.algorithm() != AlgorithmId::Sig(sig.algorithm) {
        return Err(Error::VerificationFailed);
    }
    registry::signature_scheme(sig.algorithm)?.verify(public, message, context, &sig.bytes)
}
