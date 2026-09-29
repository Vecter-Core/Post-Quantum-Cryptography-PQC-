//! X-Wing: general-purpose hybrid KEM built on X25519 and ML-KEM-768.
//!
//! Follows `draft-connolly-cfrg-xwing-kem` (CFRG). Sizes: secret key 32 bytes, public
//! key 1216 bytes, ciphertext 1120 bytes, shared secret 32 bytes.

use sha3::{Digest, Sha3_256};
use vpqc_backend_libcrux::mlkem::{self, Level};
use vpqc_core::{
    AlgorithmId, Error, Kem, KemId, KemKeyPair, PublicKey, RandomSource, Result, SecretKey,
    SharedSecret,
};
use x25519_dalek::{X25519_BASEPOINT_BYTES, x25519};
use zeroize::Zeroizing;

use crate::shake::shake256;

/// Secret key (seed) length.
pub const SECRET_KEY_LEN: usize = 32;
/// Public key length: ML-KEM-768 key (1184) followed by X25519 key (32).
pub const PUBLIC_KEY_LEN: usize = 1216;
/// Ciphertext length: ML-KEM-768 ciphertext (1088) followed by X25519 ephemeral key (32).
pub const CIPHERTEXT_LEN: usize = 1120;
/// Encapsulation randomness length (`eseed`): 32 bytes for ML-KEM, 32 for X25519.
pub const ESEED_LEN: usize = 64;

const PK_M_LEN: usize = 1184;
const CT_M_LEN: usize = 1088;

/// `XWingLabel` = `\./` `/^\` (hex `5c2e2f2f5e5c`).
const LABEL: [u8; 6] = [0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c];

/// The X-Wing KEM.
#[derive(Debug, Clone, Copy, Default)]
pub struct XWing;

struct Expanded {
    ml_kem: mlkem::KeyPair,
    sk_x: Zeroizing<[u8; 32]>,
    pk_x: [u8; 32],
}

fn expand(sk: &[u8; SECRET_KEY_LEN]) -> Expanded {
    let mut expanded = Zeroizing::new([0u8; 96]);
    shake256(&[sk], &mut *expanded);
    let mut seed = Zeroizing::new([0u8; mlkem::SEED_LEN]);
    seed.copy_from_slice(&expanded[0..64]); // d || z
    let ml_kem = mlkem::keygen(Level::L768, &seed);
    let mut sk_x = Zeroizing::new([0u8; 32]);
    sk_x.copy_from_slice(&expanded[64..96]);
    let pk_x = x25519(*sk_x, X25519_BASEPOINT_BYTES);
    Expanded { ml_kem, sk_x, pk_x }
}

fn combiner(
    ss_m: &[u8; 32],
    ss_x: &[u8; 32],
    ct_x: &[u8; 32],
    pk_x: &[u8; 32],
) -> Zeroizing<[u8; 32]> {
    let mut h = Sha3_256::new();
    h.update(ss_m);
    h.update(ss_x);
    h.update(ct_x);
    h.update(pk_x);
    h.update(LABEL);
    Zeroizing::new(h.finalize().into())
}

/// Deterministic key generation from a 32-byte secret key. Returns the 1216-byte public key.
pub fn public_key_from_secret(sk: &[u8; SECRET_KEY_LEN]) -> [u8; PUBLIC_KEY_LEN] {
    let e = expand(sk);
    let mut pk = [0u8; PUBLIC_KEY_LEN];
    pk[..PK_M_LEN].copy_from_slice(&e.ml_kem.public);
    pk[PK_M_LEN..].copy_from_slice(&e.pk_x);
    pk
}

/// Deterministic encapsulation (`EncapsulateDerand`). For testing; production code
/// should call [`Kem::encapsulate`] which draws `eseed` from the RNG.
pub fn encapsulate_derand(
    pk: &[u8],
    eseed: &[u8; ESEED_LEN],
) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>)> {
    if pk.len() != PUBLIC_KEY_LEN {
        return Err(Error::length("X-Wing public key", PUBLIC_KEY_LEN, pk.len()));
    }
    let (pk_m, pk_x) = pk.split_at(PK_M_LEN);
    let pk_x: [u8; 32] = pk_x.try_into().expect("split length is fixed");
    let mut m = Zeroizing::new([0u8; 32]);
    m.copy_from_slice(&eseed[..32]);
    let mut ek_x = Zeroizing::new([0u8; 32]);
    ek_x.copy_from_slice(&eseed[32..]);

    let ct_x = x25519(*ek_x, X25519_BASEPOINT_BYTES);
    let ss_x = Zeroizing::new(x25519(*ek_x, pk_x));
    let (ct_m, ss_m) = mlkem::encapsulate(Level::L768, pk_m, &m)?;

    let ss = combiner(&ss_m, &ss_x, &ct_x, &pk_x);
    let mut ct = Vec::with_capacity(CIPHERTEXT_LEN);
    ct.extend_from_slice(&ct_m);
    ct.extend_from_slice(&ct_x);
    Ok((ct, ss))
}

/// Decapsulate with the 32-byte secret key.
pub fn decapsulate_raw(sk: &[u8; SECRET_KEY_LEN], ct: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    if ct.len() != CIPHERTEXT_LEN {
        return Err(Error::length("X-Wing ciphertext", CIPHERTEXT_LEN, ct.len()));
    }
    let e = expand(sk);
    let (ct_m, ct_x) = ct.split_at(CT_M_LEN);
    let ct_x: [u8; 32] = ct_x.try_into().expect("split length is fixed");
    let ss_m = mlkem::decapsulate(Level::L768, &e.ml_kem.decapsulation_key, ct_m)?;
    let ss_x = Zeroizing::new(x25519(*e.sk_x, ct_x));
    Ok(combiner(&ss_m, &ss_x, &ct_x, &e.pk_x))
}

impl Kem for XWing {
    fn id(&self) -> KemId {
        KemId::XWing
    }

    fn public_key_len(&self) -> usize {
        PUBLIC_KEY_LEN
    }

    fn ciphertext_len(&self) -> usize {
        CIPHERTEXT_LEN
    }

    fn generate(&self, rng: &mut dyn RandomSource) -> Result<KemKeyPair> {
        let mut sk = Zeroizing::new([0u8; SECRET_KEY_LEN]);
        rng.fill(&mut *sk)?;
        let pk = public_key_from_secret(&sk);
        Ok(KemKeyPair {
            public: PublicKey::new(AlgorithmId::Kem(KemId::XWing), pk.to_vec()),
            secret: SecretKey::new(AlgorithmId::Kem(KemId::XWing), sk.to_vec()),
        })
    }

    fn encapsulate(
        &self,
        pk: &PublicKey,
        rng: &mut dyn RandomSource,
    ) -> Result<(Vec<u8>, SharedSecret)> {
        if pk.algorithm() != AlgorithmId::Kem(KemId::XWing) {
            return Err(Error::AlgorithmMismatch);
        }
        let mut eseed = Zeroizing::new([0u8; ESEED_LEN]);
        rng.fill(&mut *eseed)?;
        let (ct, ss) = encapsulate_derand(pk.as_bytes(), &eseed)?;
        Ok((ct, SharedSecret::new(*ss)))
    }

    fn decapsulate(&self, sk: &SecretKey, ciphertext: &[u8]) -> Result<SharedSecret> {
        if sk.algorithm() != AlgorithmId::Kem(KemId::XWing) {
            return Err(Error::AlgorithmMismatch);
        }
        let seed: &[u8; SECRET_KEY_LEN] = sk
            .expose_bytes()
            .try_into()
            .map_err(|_| Error::InvalidKey("bad X-Wing secret key length"))?;
        Ok(SharedSecret::new(*decapsulate_raw(seed, ciphertext)?))
    }
}
