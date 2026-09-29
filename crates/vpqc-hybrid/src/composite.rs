//! Composite signature: Ed25519 **and** ML-DSA-65 over the same domain-separated message.
//!
//! Construction (vpqc-composite-v1), loosely following the IETF LAMPS composite
//! signature drafts but **not wire-compatible** with them yet (labels and OIDs will be
//! aligned once the RFC is published):
//!
//! ```text
//! M'  = "vpqc-composite-v1" || 0x00 || be16(sig_id) || len(ctx) || ctx || SHA3-512(M)
//! sig = Ed25519.Sign(M') || ML-DSA-65.Sign(M', ctx = "vpqc-composite-v1")
//! ```
//!
//! Both signatures bind the same `M'`, so a signature cannot be split and reused as a
//! standalone Ed25519 or ML-DSA signature, and verification demands both. Secret key:
//! a 32-byte seed expanded with SHAKE256 into the Ed25519 seed and the ML-DSA seed.

use vpqc_backend_libcrux::mldsa::{self, Level};
use vpqc_core::{
    AlgorithmId, Error, PublicKey, RandomSource, Result, SecretKey, SigId, SignatureScheme,
};
use zeroize::Zeroizing;

use crate::ed25519::{ed_public, ed_sign, ed_verify, representative};
use crate::shake::shake256;

const LABEL: &[u8] = b"vpqc-composite-v1";
const KEYGEN_LABEL: &[u8] = b"vpqc-composite-v1-keygen";
const ED_PK_LEN: usize = 32;
const ED_SIG_LEN: usize = 64;

/// Composite Ed25519 + ML-DSA-65.
#[derive(Debug, Clone, Copy, Default)]
pub struct CompositeEd25519MlDsa65;

fn expand(seed: &[u8; 32]) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    let mut out = Zeroizing::new([0u8; 64]);
    shake256(&[KEYGEN_LABEL, seed], &mut *out);
    let mut ed = Zeroizing::new([0u8; 32]);
    let mut ml = Zeroizing::new([0u8; 32]);
    ed.copy_from_slice(&out[..32]);
    ml.copy_from_slice(&out[32..]);
    (ed, ml)
}

impl SignatureScheme for CompositeEd25519MlDsa65 {
    fn id(&self) -> SigId {
        SigId::Ed25519MlDsa65
    }

    fn signature_len(&self) -> usize {
        ED_SIG_LEN + Level::L65.signature_len()
    }

    fn generate(&self, rng: &mut dyn RandomSource) -> Result<(PublicKey, SecretKey)> {
        let mut seed = Zeroizing::new([0u8; 32]);
        rng.fill(&mut *seed)?;
        let (ed_seed, ml_seed) = expand(&seed);
        let (vk, _) = mldsa::keygen(Level::L65, &ml_seed);
        let mut pk = Vec::with_capacity(ED_PK_LEN + vk.len());
        pk.extend_from_slice(&ed_public(&ed_seed));
        pk.extend_from_slice(&vk);
        Ok((
            PublicKey::new(AlgorithmId::Sig(SigId::Ed25519MlDsa65), pk),
            SecretKey::new(AlgorithmId::Sig(SigId::Ed25519MlDsa65), seed.to_vec()),
        ))
    }

    fn sign(
        &self,
        sk: &SecretKey,
        message: &[u8],
        context: &[u8],
        rng: &mut dyn RandomSource,
    ) -> Result<Vec<u8>> {
        if sk.algorithm() != AlgorithmId::Sig(SigId::Ed25519MlDsa65) {
            return Err(Error::AlgorithmMismatch);
        }
        if context.len() > 255 {
            return Err(Error::ContextTooLong);
        }
        let seed: &[u8; 32] = sk
            .expose_bytes()
            .try_into()
            .map_err(|_| Error::InvalidKey("bad composite secret key length"))?;
        let (ed_seed, ml_seed) = expand(seed);
        let (_, ml_sk) = mldsa::keygen(Level::L65, &ml_seed);
        let rep = representative(LABEL, SigId::Ed25519MlDsa65, context, message);

        let mut rnd = Zeroizing::new([0u8; mldsa::SIGN_RANDOMNESS_LEN]);
        rng.fill(&mut *rnd)?;
        let ml_sig = mldsa::sign(Level::L65, &ml_sk, &rep, LABEL, &rnd)?;
        let ed_sig = ed_sign(&ed_seed, &rep);

        let mut sig = Vec::with_capacity(ED_SIG_LEN + ml_sig.len());
        sig.extend_from_slice(&ed_sig);
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
        if pk.algorithm() != AlgorithmId::Sig(SigId::Ed25519MlDsa65) {
            return Err(Error::AlgorithmMismatch);
        }
        if context.len() > 255 {
            return Err(Error::ContextTooLong);
        }
        let expected_pk = ED_PK_LEN + Level::L65.public_key_len();
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
        let (ed_pk, ml_pk) = pk.as_bytes().split_at(ED_PK_LEN);
        let (ed_sig, ml_sig) = signature.split_at(ED_SIG_LEN);
        let rep = representative(LABEL, SigId::Ed25519MlDsa65, context, message);

        // Evaluate both, then combine: no early exit on the first failure.
        let ed = ed_verify(ed_pk, &rep, ed_sig);
        let ml = mldsa::verify(Level::L65, ml_pk, &rep, LABEL, ml_sig);
        if ed.is_ok() && ml.is_ok() {
            Ok(())
        } else {
            Err(Error::VerificationFailed)
        }
    }
}
