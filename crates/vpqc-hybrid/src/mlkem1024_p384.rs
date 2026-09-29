//! `MLKEM1024-P384`: hybrid KEM of ML-KEM-1024 and NIST P-384.
//!
//! Follows `draft-irtf-cfrg-concrete-hybrid-kems` (CG framework of
//! `draft-irtf-cfrg-hybrid-kems`), with SHAKE256 as PRG and SHA3-256 as KDF, and is checked
//! against the official test vectors.
//!
//! Sizes: secret key (seed) 32 bytes, public key 1665, ciphertext 1665, shared secret 32.

use p384::PublicKey as P384Public;
use p384::SecretKey as P384Secret;
use p384::ecdh::diffie_hellman;
use sha3::{Digest, Sha3_256};
use vpqc_backend_libcrux::mlkem::{self, Level};
use vpqc_core::{
    AlgorithmId, Error, Kem, KemId, KemKeyPair, PublicKey, RandomSource, Result, SecretKey,
    SharedSecret,
};
use zeroize::Zeroizing;

use crate::shake::shake256;

/// Secret key (seed) length.
pub const SECRET_KEY_LEN: usize = 32;
/// Public key length: ML-KEM-1024 key (1568) followed by an uncompressed P-384 point (97).
pub const PUBLIC_KEY_LEN: usize = 1665;
/// Ciphertext length: ML-KEM-1024 ciphertext (1568) followed by an ephemeral P-384 point (97).
pub const CIPHERTEXT_LEN: usize = 1665;
/// Encapsulation randomness: 32 bytes for ML-KEM, 48 for the ephemeral P-384 scalar.
pub const RANDOMNESS_LEN: usize = 80;

const PK_PQ_LEN: usize = 1568;
const POINT_LEN: usize = 97;
const SEED_PQ_LEN: usize = 64;
const SEED_T_LEN: usize = 48;
const LABEL: &[u8] = b"MLKEM1024-P384";

/// The MLKEM1024-P384 hybrid KEM.
#[derive(Debug, Clone, Copy, Default)]
pub struct MlKem1024P384;

/// `RandomScalar` for P-384: the seed is used as a big-endian scalar; zero or values not
/// below the group order are rejected. With a uniformly random 48-byte seed this fails with
/// probability below 2^-190, and the draft treats failure as an error.
fn random_scalar(seed: &[u8]) -> Result<P384Secret> {
    P384Secret::from_slice(seed)
        .map_err(|_| Error::Backend("P-384 scalar rejection sampling failed"))
}

fn point_bytes(sk: &P384Secret) -> Result<[u8; POINT_LEN]> {
    let bytes = sk.public_key().to_sec1_bytes();
    bytes
        .as_ref()
        .try_into()
        .map_err(|_| Error::Backend("unexpected P-384 point encoding"))
}

struct Expanded {
    ml_kem: mlkem::KeyPair,
    dk_t: P384Secret,
    ek_t: [u8; POINT_LEN],
}

fn expand(seed: &[u8; SECRET_KEY_LEN]) -> Result<Expanded> {
    let mut full = Zeroizing::new([0u8; SEED_PQ_LEN + SEED_T_LEN]);
    shake256(&[seed], &mut *full);
    let mut seed_pq = Zeroizing::new([0u8; SEED_PQ_LEN]);
    seed_pq.copy_from_slice(&full[..SEED_PQ_LEN]);
    let ml_kem = mlkem::keygen(Level::L1024, &seed_pq);
    let dk_t = random_scalar(&full[SEED_PQ_LEN..])?;
    let ek_t = point_bytes(&dk_t)?;
    Ok(Expanded { ml_kem, dk_t, ek_t })
}

fn combiner(ss_pq: &[u8; 32], ss_t: &[u8], ct_t: &[u8], ek_t: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut h = Sha3_256::new();
    h.update(ss_pq);
    h.update(ss_t);
    h.update(ct_t);
    h.update(ek_t);
    h.update(LABEL);
    Zeroizing::new(h.finalize().into())
}

/// Public key for a 32-byte secret key (deterministic `DeriveKeyPair`).
pub fn public_key_from_secret(sk: &[u8; SECRET_KEY_LEN]) -> Result<Vec<u8>> {
    let e = expand(sk)?;
    let mut pk = Vec::with_capacity(PUBLIC_KEY_LEN);
    pk.extend_from_slice(&e.ml_kem.public);
    pk.extend_from_slice(&e.ek_t);
    Ok(pk)
}

/// Big-endian private scalar of the P-384 component (for test vectors).
pub fn t_component_secret(sk: &[u8; SECRET_KEY_LEN]) -> Result<Zeroizing<Vec<u8>>> {
    Ok(Zeroizing::new(
        expand(sk)?.dk_t.to_bytes().as_slice().to_vec(),
    ))
}

/// Deterministic encapsulation (`EncapsDerand`), for testing.
pub fn encapsulate_derand(
    pk: &[u8],
    randomness: &[u8; RANDOMNESS_LEN],
) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>)> {
    if pk.len() != PUBLIC_KEY_LEN {
        return Err(Error::length(
            "MLKEM1024-P384 public key",
            PUBLIC_KEY_LEN,
            pk.len(),
        ));
    }
    let (ek_pq, ek_t) = pk.split_at(PK_PQ_LEN);
    let mut m = Zeroizing::new([0u8; 32]);
    m.copy_from_slice(&randomness[..32]);
    let (ct_pq, ss_pq) = mlkem::encapsulate(Level::L1024, ek_pq, &m)?;

    let sk_e = random_scalar(&randomness[32..])?;
    let ct_t = point_bytes(&sk_e)?;
    let recipient = P384Public::from_sec1_bytes(ek_t)
        .map_err(|_| Error::InvalidKey("invalid P-384 public key"))?;
    let ss_t = Zeroizing::new(
        diffie_hellman(sk_e.to_nonzero_scalar(), recipient.as_affine())
            .raw_secret_bytes()
            .as_slice()
            .to_vec(),
    );

    let ss = combiner(&ss_pq, &ss_t, &ct_t, ek_t);
    let mut ct = Vec::with_capacity(CIPHERTEXT_LEN);
    ct.extend_from_slice(&ct_pq);
    ct.extend_from_slice(&ct_t);
    Ok((ct, ss))
}

/// Decapsulate with the 32-byte secret key. An invalid P-384 point in the ciphertext is an
/// error (explicit rejection; it operates only on public data).
pub fn decapsulate_raw(sk: &[u8; SECRET_KEY_LEN], ct: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    if ct.len() != CIPHERTEXT_LEN {
        return Err(Error::length(
            "MLKEM1024-P384 ciphertext",
            CIPHERTEXT_LEN,
            ct.len(),
        ));
    }
    let e = expand(sk)?;
    let (ct_pq, ct_t) = ct.split_at(PK_PQ_LEN);
    let ephemeral = P384Public::from_sec1_bytes(ct_t)
        .map_err(|_| Error::Backend("invalid P-384 ciphertext"))?;
    let ss_pq = mlkem::decapsulate(Level::L1024, &e.ml_kem.decapsulation_key, ct_pq)?;
    let ss_t = Zeroizing::new(
        diffie_hellman(e.dk_t.to_nonzero_scalar(), ephemeral.as_affine())
            .raw_secret_bytes()
            .as_slice()
            .to_vec(),
    );
    Ok(combiner(&ss_pq, &ss_t, ct_t, &e.ek_t))
}

impl Kem for MlKem1024P384 {
    fn id(&self) -> KemId {
        KemId::MlKem1024P384
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
        let pk = public_key_from_secret(&sk)?;
        Ok(KemKeyPair {
            public: PublicKey::new(AlgorithmId::Kem(KemId::MlKem1024P384), pk),
            secret: SecretKey::new(AlgorithmId::Kem(KemId::MlKem1024P384), sk.to_vec()),
        })
    }

    fn encapsulate(
        &self,
        pk: &PublicKey,
        rng: &mut dyn RandomSource,
    ) -> Result<(Vec<u8>, SharedSecret)> {
        if pk.algorithm() != AlgorithmId::Kem(KemId::MlKem1024P384) {
            return Err(Error::AlgorithmMismatch);
        }
        let mut randomness = Zeroizing::new([0u8; RANDOMNESS_LEN]);
        rng.fill(&mut *randomness)?;
        let (ct, ss) = encapsulate_derand(pk.as_bytes(), &randomness)?;
        Ok((ct, SharedSecret::new(*ss)))
    }

    fn decapsulate(&self, sk: &SecretKey, ciphertext: &[u8]) -> Result<SharedSecret> {
        if sk.algorithm() != AlgorithmId::Kem(KemId::MlKem1024P384) {
            return Err(Error::AlgorithmMismatch);
        }
        let seed: &[u8; SECRET_KEY_LEN] = sk
            .expose_bytes()
            .try_into()
            .map_err(|_| Error::InvalidKey("bad MLKEM1024-P384 secret key length"))?;
        Ok(SharedSecret::new(*decapsulate_raw(seed, ciphertext)?))
    }
}
