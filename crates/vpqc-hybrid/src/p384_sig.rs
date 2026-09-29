//! ECDSA over NIST P-384 (SHA-384) as the classical half of the `high` profile composite.

use p384::SecretKey as P384Secret;
use p384::ecdsa::signature::{Signer, Verifier};
use p384::ecdsa::{Signature, SigningKey, VerifyingKey};
use vpqc_backend_libcrux::mldsa::Level;
use vpqc_core::{Error, Result, SigId};
use zeroize::Zeroizing;

use crate::composite::{ClassicalHalf, Composite, ExpandedSeed};
use crate::shake::shake256;

/// ECDSA-P384 half of the `ECDSA-P384 + ML-DSA-87` composite.
///
/// Signatures are deterministic (RFC 6979) and normalized to low-S; verification rejects
/// high-S encodings, so each message has one canonical signature per key and nonce.
#[derive(Debug, Clone, Copy)]
pub struct EcdsaP384Half;

const KEYGEN_LABEL: &[u8] = b"vpqc-composite-v1-p384-keygen";

impl ClassicalHalf for EcdsaP384Half {
    const ID: SigId = SigId::EcdsaP384MlDsa87;
    const ML_LEVEL: Level = Level::L87;
    /// Uncompressed SEC1 point.
    const PK_LEN: usize = 97;
    /// Fixed-size `r || s`.
    const SIG_LEN: usize = 96;

    fn expand(seed: &[u8; 32]) -> Result<ExpandedSeed> {
        // 48 bytes for the scalar plus 32 for the ML-DSA seed. A counter makes the scalar
        // derivation total: values outside [1, n-1] (probability < 2^-190) trigger a retry.
        for counter in 0u8..=255 {
            let mut out = Zeroizing::new([0u8; 80]);
            shake256(&[KEYGEN_LABEL, seed, &[counter]], &mut *out);
            if let Ok(sk) = P384Secret::from_slice(&out[..48]) {
                let mut ml = Zeroizing::new([0u8; 32]);
                ml.copy_from_slice(&out[48..]);
                return Ok((Zeroizing::new(sk.to_bytes().as_slice().to_vec()), ml));
            }
        }
        Err(Error::Backend("P-384 key derivation failed"))
    }

    fn public(secret: &[u8]) -> Result<Vec<u8>> {
        let sk =
            P384Secret::from_slice(secret).map_err(|_| Error::InvalidKey("bad P-384 secret"))?;
        Ok(sk.public_key().to_sec1_bytes().to_vec())
    }

    fn sign(secret: &[u8], rep: &[u8]) -> Result<Vec<u8>> {
        let sk =
            P384Secret::from_slice(secret).map_err(|_| Error::InvalidKey("bad P-384 secret"))?;
        let signing = SigningKey::from(&sk);
        let sig: Signature = signing
            .try_sign(rep)
            .map_err(|_| Error::Backend("ECDSA signing failed"))?;
        Ok(sig.normalize_s().to_bytes().as_slice().to_vec())
    }

    fn verify(pk: &[u8], rep: &[u8], sig: &[u8]) -> Result<()> {
        let vk = VerifyingKey::from_sec1_bytes(pk)
            .map_err(|_| Error::InvalidKey("bad P-384 public key"))?;
        let sig = Signature::from_slice(sig).map_err(|_| Error::VerificationFailed)?;
        if sig.normalize_s().to_bytes() != sig.to_bytes() {
            return Err(Error::VerificationFailed); // high-S: not canonical
        }
        vk.verify(rep, &sig).map_err(|_| Error::VerificationFailed)
    }
}

/// The composite `ECDSA-P384 + ML-DSA-87` scheme.
pub type CompositeEcdsaP384MlDsa87 = Composite<EcdsaP384Half>;
