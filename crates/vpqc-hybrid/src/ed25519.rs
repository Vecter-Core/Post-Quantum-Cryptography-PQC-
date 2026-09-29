use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha3::{Digest, Sha3_512};
use vpqc_core::{
    AlgorithmId, Error, PublicKey, RandomSource, Result, SecretKey, SigId, SignatureScheme,
};
use zeroize::Zeroizing;

const LABEL: &[u8] = b"vpqc-ed25519-v1";

/// Domain-separated message representative: `label || len(ctx) || ctx || SHA3-512(msg)`.
pub(crate) fn representative(
    label: &[u8],
    sig_id: SigId,
    context: &[u8],
    message: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(label.len() + 4 + context.len() + 64);
    out.extend_from_slice(label);
    out.push(0);
    out.extend_from_slice(&sig_id.to_u16().to_be_bytes());
    out.push(context.len() as u8);
    out.extend_from_slice(context);
    out.extend_from_slice(&Sha3_512::digest(message));
    out
}

/// Ed25519 (RFC 8032) with vpqc context binding.
///
/// Classical only: **not** quantum-resistant. Use for short-lived authentication
/// (profile `fast-auth`), never for certificates, firmware or archives.
#[derive(Debug, Clone, Copy, Default)]
pub struct Ed25519;

pub(crate) fn ed_sign(seed: &[u8; 32], rep: &[u8]) -> [u8; 64] {
    let sk = SigningKey::from_bytes(seed);
    sk.sign(rep).to_bytes()
}

pub(crate) fn ed_verify(pk: &[u8], rep: &[u8], sig: &[u8]) -> Result<()> {
    let pk: [u8; 32] = pk
        .try_into()
        .map_err(|_| Error::InvalidKey("bad Ed25519 public key length"))?;
    let vk =
        VerifyingKey::from_bytes(&pk).map_err(|_| Error::InvalidKey("bad Ed25519 public key"))?;
    let sig: [u8; 64] = sig.try_into().map_err(|_| Error::VerificationFailed)?;
    vk.verify_strict(rep, &Signature::from_bytes(&sig))
        .map_err(|_| Error::VerificationFailed)
}

pub(crate) fn ed_public(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

impl SignatureScheme for Ed25519 {
    fn id(&self) -> SigId {
        SigId::Ed25519
    }

    fn signature_len(&self) -> usize {
        64
    }

    fn generate(&self, rng: &mut dyn RandomSource) -> Result<(PublicKey, SecretKey)> {
        let mut seed = Zeroizing::new([0u8; 32]);
        rng.fill(&mut *seed)?;
        Ok((
            PublicKey::new(AlgorithmId::Sig(SigId::Ed25519), ed_public(&seed).to_vec()),
            SecretKey::new(AlgorithmId::Sig(SigId::Ed25519), seed.to_vec()),
        ))
    }

    fn sign(
        &self,
        sk: &SecretKey,
        message: &[u8],
        context: &[u8],
        _rng: &mut dyn RandomSource,
    ) -> Result<Vec<u8>> {
        if sk.algorithm() != AlgorithmId::Sig(SigId::Ed25519) {
            return Err(Error::AlgorithmMismatch);
        }
        if context.len() > 255 {
            return Err(Error::ContextTooLong);
        }
        let seed: &[u8; 32] = sk
            .expose_bytes()
            .try_into()
            .map_err(|_| Error::InvalidKey("bad Ed25519 secret key length"))?;
        let rep = representative(LABEL, SigId::Ed25519, context, message);
        Ok(ed_sign(seed, &rep).to_vec())
    }

    fn verify(
        &self,
        pk: &PublicKey,
        message: &[u8],
        context: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        if pk.algorithm() != AlgorithmId::Sig(SigId::Ed25519) {
            return Err(Error::AlgorithmMismatch);
        }
        if context.len() > 255 {
            return Err(Error::ContextTooLong);
        }
        let rep = representative(LABEL, SigId::Ed25519, context, message);
        ed_verify(pk.as_bytes(), &rep, signature)
    }
}
