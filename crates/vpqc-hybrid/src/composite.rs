//! Composite signatures: a classical signature **and** an ML-DSA signature over the same
//! domain-separated message. Both must verify.
//!
//! Construction (vpqc-composite-v1), loosely following the IETF LAMPS composite signature
//! drafts but **not wire-compatible** with them yet (labels and OIDs will be aligned once the
//! RFC is published):
//!
//! ```text
//! M'  = "vpqc-composite-v1" || 0x00 || be16(sig_id) || len(ctx) || ctx || SHA3-512(M)
//! sig = Classical.Sign(M') || ML-DSA.Sign(M', ctx = "vpqc-composite-v1")
//! ```
//!
//! Both signatures bind the same `M'` (which contains the composite's algorithm id and the
//! caller's context), so a signature cannot be split and reused as a standalone classical or
//! ML-DSA signature, and verification demands both. Secret key: a 32-byte seed expanded with
//! SHAKE256 into the classical key and the ML-DSA seed.

use std::marker::PhantomData;

use vpqc_backend_libcrux::mldsa::{self, Level};
use vpqc_core::{
    AlgorithmId, Error, PublicKey, RandomSource, Result, SecretKey, SigId, SignatureScheme,
};
use zeroize::Zeroizing;

use crate::ed25519::representative;

const LABEL: &[u8] = b"vpqc-composite-v1";

/// Result of expanding a composite seed: `(classical secret, ML-DSA seed)`.
pub type ExpandedSeed = (Zeroizing<Vec<u8>>, Zeroizing<[u8; 32]>);

/// The classical half of a composite signature.
pub trait ClassicalHalf: Send + Sync + 'static {
    /// Identifier of the composite this half belongs to.
    const ID: SigId;
    /// ML-DSA parameter set paired with this classical scheme.
    const ML_LEVEL: Level;
    /// Public key length of the classical scheme.
    const PK_LEN: usize;
    /// Signature length of the classical scheme.
    const SIG_LEN: usize;

    /// Expand the 32-byte composite seed into `(classical secret, ML-DSA seed)`.
    fn expand(seed: &[u8; 32]) -> Result<ExpandedSeed>;
    /// Public key for a classical secret.
    fn public(secret: &[u8]) -> Result<Vec<u8>>;
    /// Sign the representative.
    fn sign(secret: &[u8], rep: &[u8]) -> Result<Vec<u8>>;
    /// Verify a classical signature over the representative.
    fn verify(pk: &[u8], rep: &[u8], sig: &[u8]) -> Result<()>;
}

/// A composite signature scheme built from a classical half and ML-DSA.
#[derive(Debug, Clone, Copy, Default)]
pub struct Composite<H: ClassicalHalf>(pub PhantomData<H>);

impl<H: ClassicalHalf> Composite<H> {
    /// Create the (stateless) scheme.
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<H: ClassicalHalf> SignatureScheme for Composite<H> {
    fn id(&self) -> SigId {
        H::ID
    }

    fn signature_len(&self) -> usize {
        H::SIG_LEN + H::ML_LEVEL.signature_len()
    }

    fn generate(&self, rng: &mut dyn RandomSource) -> Result<(PublicKey, SecretKey)> {
        let mut seed = Zeroizing::new([0u8; 32]);
        rng.fill(&mut *seed)?;
        let (classical, ml_seed) = H::expand(&seed)?;
        let (vk, _) = mldsa::keygen(H::ML_LEVEL, &ml_seed);
        let mut pk = H::public(&classical)?;
        debug_assert_eq!(pk.len(), H::PK_LEN);
        pk.extend_from_slice(&vk);
        Ok((
            PublicKey::new(AlgorithmId::Sig(H::ID), pk),
            SecretKey::new(AlgorithmId::Sig(H::ID), seed.to_vec()),
        ))
    }

    fn sign(
        &self,
        sk: &SecretKey,
        message: &[u8],
        context: &[u8],
        rng: &mut dyn RandomSource,
    ) -> Result<Vec<u8>> {
        if sk.algorithm() != AlgorithmId::Sig(H::ID) {
            return Err(Error::AlgorithmMismatch);
        }
        if context.len() > 255 {
            return Err(Error::ContextTooLong);
        }
        let seed: &[u8; 32] = sk
            .expose_bytes()
            .try_into()
            .map_err(|_| Error::InvalidKey("bad composite secret key length"))?;
        let (classical, ml_seed) = H::expand(seed)?;
        let (_, ml_sk) = mldsa::keygen(H::ML_LEVEL, &ml_seed);
        let rep = representative(LABEL, H::ID, context, message);

        let mut rnd = Zeroizing::new([0u8; mldsa::SIGN_RANDOMNESS_LEN]);
        rng.fill(&mut *rnd)?;
        let ml_sig = mldsa::sign(H::ML_LEVEL, &ml_sk, &rep, LABEL, &rnd)?;
        let mut sig = H::sign(&classical, &rep)?;
        debug_assert_eq!(sig.len(), H::SIG_LEN);
        sig.extend_from_slice(&ml_sig);
        Ok(sig)
    }

    fn verify(
        &self,
        pk: &PublicKey,
        message: &[u8],
        context: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        if pk.algorithm() != AlgorithmId::Sig(H::ID) {
            return Err(Error::AlgorithmMismatch);
        }
        if context.len() > 255 {
            return Err(Error::ContextTooLong);
        }
        let expected_pk = H::PK_LEN + H::ML_LEVEL.public_key_len();
        if pk.as_bytes().len() != expected_pk {
            return Err(Error::length(
                "composite public key",
                expected_pk,
                pk.as_bytes().len(),
            ));
        }
        if signature.len() != self.signature_len() {
            return Err(Error::VerificationFailed);
        }
        let (classical_pk, ml_pk) = pk.as_bytes().split_at(H::PK_LEN);
        let (classical_sig, ml_sig) = signature.split_at(H::SIG_LEN);
        let rep = representative(LABEL, H::ID, context, message);

        // Evaluate both, then combine: no early exit on the first failure.
        let classical = H::verify(classical_pk, &rep, classical_sig);
        let ml = mldsa::verify(H::ML_LEVEL, ml_pk, &rep, LABEL, ml_sig);
        if classical.is_ok() && ml.is_ok() {
            Ok(())
        } else {
            Err(Error::VerificationFailed)
        }
    }
}

/// Ed25519 half of the `Ed25519 + ML-DSA-65` composite.
#[derive(Debug, Clone, Copy)]
pub struct Ed25519Half;

impl ClassicalHalf for Ed25519Half {
    const ID: SigId = SigId::Ed25519MlDsa65;
    const ML_LEVEL: Level = Level::L65;
    const PK_LEN: usize = 32;
    const SIG_LEN: usize = 64;

    fn expand(seed: &[u8; 32]) -> Result<ExpandedSeed> {
        let mut out = Zeroizing::new([0u8; 64]);
        crate::shake::shake256(&[b"vpqc-composite-v1-keygen", seed], &mut *out);
        let mut ml = Zeroizing::new([0u8; 32]);
        ml.copy_from_slice(&out[32..]);
        Ok((Zeroizing::new(out[..32].to_vec()), ml))
    }

    fn public(secret: &[u8]) -> Result<Vec<u8>> {
        let seed: &[u8; 32] = secret
            .try_into()
            .map_err(|_| Error::InvalidKey("bad Ed25519 seed"))?;
        Ok(crate::ed25519::ed_public(seed).to_vec())
    }

    fn sign(secret: &[u8], rep: &[u8]) -> Result<Vec<u8>> {
        let seed: &[u8; 32] = secret
            .try_into()
            .map_err(|_| Error::InvalidKey("bad Ed25519 seed"))?;
        Ok(crate::ed25519::ed_sign(seed, rep).to_vec())
    }

    fn verify(pk: &[u8], rep: &[u8], sig: &[u8]) -> Result<()> {
        crate::ed25519::ed_verify(pk, rep, sig)
    }
}

/// The composite `Ed25519 + ML-DSA-65` scheme.
pub type CompositeEd25519MlDsa65 = Composite<Ed25519Half>;
