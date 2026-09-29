//! Byte-level ML-DSA primitives with explicit randomness.

use vpqc_core::{Error, Result};
use zeroize::Zeroizing;

/// Length of the key-generation seed `xi`.
pub const SEED_LEN: usize = 32;
/// Length of the per-signature randomness (hedged signing).
pub const SIGN_RANDOMNESS_LEN: usize = 32;

/// ML-DSA parameter set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// ML-DSA-65 (NIST category 3).
    L65,
    /// ML-DSA-87 (NIST category 5).
    L87,
}

impl Level {
    /// Verification key length.
    pub const fn public_key_len(self) -> usize {
        match self {
            Level::L65 => 1952,
            Level::L87 => 2592,
        }
    }

    /// Signature length.
    pub const fn signature_len(self) -> usize {
        match self {
            Level::L65 => 3309,
            Level::L87 => 4627,
        }
    }

    const fn signing_key_len(self) -> usize {
        match self {
            Level::L65 => 4032,
            Level::L87 => 4896,
        }
    }
}

macro_rules! level_fns {
    ($keygen:ident, $sign:ident, $verify:ident, $m:ident, $Sk:ident, $Vk:ident, $Sig:ident) => {
        fn $keygen(seed: [u8; SEED_LEN]) -> (Vec<u8>, Zeroizing<Vec<u8>>) {
            let kp = libcrux_ml_dsa::$m::generate_key_pair(seed);
            (
                kp.verification_key.as_slice().to_vec(),
                Zeroizing::new(kp.signing_key.as_slice().to_vec()),
            )
        }

        fn $sign(
            sk: &[u8],
            msg: &[u8],
            ctx: &[u8],
            rnd: [u8; SIGN_RANDOMNESS_LEN],
        ) -> Result<Vec<u8>> {
            let sk: libcrux_ml_dsa::$m::$Sk = libcrux_ml_dsa::$m::$Sk::new(
                sk.try_into()
                    .map_err(|_| Error::InvalidKey("bad ML-DSA signing key"))?,
            );
            let sig = libcrux_ml_dsa::$m::sign(&sk, msg, ctx, rnd)
                .map_err(|_| Error::Backend("ML-DSA signing failed"))?;
            Ok(sig.as_slice().to_vec())
        }

        fn $verify(vk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> Result<()> {
            let vk = libcrux_ml_dsa::$m::$Vk::new(
                vk.try_into()
                    .map_err(|_| Error::InvalidKey("bad ML-DSA verification key"))?,
            );
            let sig = libcrux_ml_dsa::$m::$Sig::new(
                sig.try_into().map_err(|_| Error::VerificationFailed)?,
            );
            libcrux_ml_dsa::$m::verify(&vk, msg, ctx, &sig).map_err(|_| Error::VerificationFailed)
        }
    };
}

level_fns!(
    keygen_65,
    sign_65,
    verify_65,
    ml_dsa_65,
    MLDSA65SigningKey,
    MLDSA65VerificationKey,
    MLDSA65Signature
);
level_fns!(
    keygen_87,
    sign_87,
    verify_87,
    ml_dsa_87,
    MLDSA87SigningKey,
    MLDSA87VerificationKey,
    MLDSA87Signature
);

/// Deterministic key generation from the 32-byte seed `xi` (FIPS 204 `KeyGen_internal`).
///
/// Returns `(verification_key, expanded_signing_key)`.
pub fn keygen(level: Level, seed: &[u8; SEED_LEN]) -> (Vec<u8>, Zeroizing<Vec<u8>>) {
    match level {
        Level::L65 => keygen_65(*seed),
        Level::L87 => keygen_87(*seed),
    }
}

/// Sign with an expanded signing key. `context` must be at most 255 bytes.
pub fn sign(
    level: Level,
    signing_key: &[u8],
    message: &[u8],
    context: &[u8],
    randomness: &[u8; SIGN_RANDOMNESS_LEN],
) -> Result<Vec<u8>> {
    if context.len() > 255 {
        return Err(Error::ContextTooLong);
    }
    if signing_key.len() != level.signing_key_len() {
        return Err(Error::length(
            "ML-DSA signing key",
            level.signing_key_len(),
            signing_key.len(),
        ));
    }
    match level {
        Level::L65 => sign_65(signing_key, message, context, *randomness),
        Level::L87 => sign_87(signing_key, message, context, *randomness),
    }
}

/// Verify a signature. Returns [`Error::VerificationFailed`] on any failure.
pub fn verify(
    level: Level,
    verification_key: &[u8],
    message: &[u8],
    context: &[u8],
    signature: &[u8],
) -> Result<()> {
    if context.len() > 255 {
        return Err(Error::ContextTooLong);
    }
    if verification_key.len() != level.public_key_len() {
        return Err(Error::length(
            "ML-DSA verification key",
            level.public_key_len(),
            verification_key.len(),
        ));
    }
    if signature.len() != level.signature_len() {
        return Err(Error::VerificationFailed);
    }
    match level {
        Level::L65 => verify_65(verification_key, message, context, signature),
        Level::L87 => verify_87(verification_key, message, context, signature),
    }
}
