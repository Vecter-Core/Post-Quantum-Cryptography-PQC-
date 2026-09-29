//! HPKE KEM interface for ML-KEM and the PQ/T hybrids (draft-ietf-hpke-pq).

use vpqc_backend_libcrux::mlkem::{self, Level};
use vpqc_core::{Error, OsRng, RandomSource, Result};
use vpqc_hybrid::{mlkem1024_p384, xwing};
use zeroize::Zeroizing;

use crate::kdf::Kdf;

/// HPKE KEM identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kem {
    /// ML-KEM-768 (`0x0041`).
    MlKem768,
    /// ML-KEM-1024 (`0x0042`).
    MlKem1024,
    /// MLKEM1024-P384 (`0x0051`).
    MlKem1024P384,
    /// MLKEM768-X25519, i.e. X-Wing (`0x647a`).
    XWing,
}

impl Kem {
    /// IANA identifier.
    pub const fn id(self) -> u16 {
        match self {
            Kem::MlKem768 => 0x0041,
            Kem::MlKem1024 => 0x0042,
            Kem::MlKem1024P384 => 0x0051,
            Kem::XWing => 0x647a,
        }
    }

    /// Parse an IANA identifier.
    pub fn from_id(id: u16) -> Result<Self> {
        Ok(match id {
            0x0041 => Kem::MlKem768,
            0x0042 => Kem::MlKem1024,
            0x0051 => Kem::MlKem1024P384,
            0x647a => Kem::XWing,
            _ => return Err(Error::Unsupported("HPKE KEM")),
        })
    }

    /// Private key length `Nsk`.
    pub const fn n_sk(self) -> usize {
        match self {
            Kem::MlKem768 | Kem::MlKem1024 => 64,
            Kem::MlKem1024P384 | Kem::XWing => 32,
        }
    }

    /// Public key length `Npk`.
    pub const fn n_pk(self) -> usize {
        match self {
            Kem::MlKem768 => 1184,
            Kem::MlKem1024 => 1568,
            Kem::MlKem1024P384 => mlkem1024_p384::PUBLIC_KEY_LEN,
            Kem::XWing => xwing::PUBLIC_KEY_LEN,
        }
    }

    /// Encapsulated key length `Nenc`.
    pub const fn n_enc(self) -> usize {
        match self {
            Kem::MlKem768 => 1088,
            Kem::MlKem1024 => 1568,
            Kem::MlKem1024P384 => mlkem1024_p384::CIPHERTEXT_LEN,
            Kem::XWing => xwing::CIPHERTEXT_LEN,
        }
    }

    /// Randomness consumed by one encapsulation.
    pub const fn n_random(self) -> usize {
        match self {
            Kem::MlKem768 | Kem::MlKem1024 => 32,
            Kem::MlKem1024P384 => mlkem1024_p384::RANDOMNESS_LEN,
            Kem::XWing => xwing::ESEED_LEN,
        }
    }

    fn suite_id(self) -> [u8; 5] {
        let id = self.id().to_be_bytes();
        [b'K', b'E', b'M', id[0], id[1]]
    }

    fn ml_level(self) -> Option<Level> {
        match self {
            Kem::MlKem768 => Some(Level::L768),
            Kem::MlKem1024 => Some(Level::L1024),
            _ => None,
        }
    }
}

fn public_key(kem: Kem, sk: &[u8]) -> Result<Vec<u8>> {
    if sk.len() != kem.n_sk() {
        return Err(Error::length("HPKE private key", kem.n_sk(), sk.len()));
    }
    match kem {
        Kem::MlKem768 | Kem::MlKem1024 => {
            let seed: &[u8; 64] = sk.try_into().expect("length checked");
            Ok(mlkem::keygen(kem.ml_level().expect("ML-KEM"), seed).public)
        }
        Kem::XWing => {
            Ok(xwing::public_key_from_secret(sk.try_into().expect("length checked")).to_vec())
        }
        Kem::MlKem1024P384 => {
            mlkem1024_p384::public_key_from_secret(sk.try_into().expect("length checked"))
        }
    }
}

/// `DeriveKeyPair(ikm)`: `seed = SHAKE256.LabeledDerive(ikm, "DeriveKeyPair", "", Nsk)`.
/// Returns `(private key, public key)`.
pub fn derive_key_pair(kem: Kem, ikm: &[u8]) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
    let sk = Zeroizing::new(Kdf::Shake256.labeled_derive(
        &kem.suite_id(),
        ikm,
        b"DeriveKeyPair",
        b"",
        kem.n_sk(),
    )?);
    let pk = public_key(kem, &sk)?;
    Ok((sk, pk))
}

/// `GenerateKeyPair()`. Returns `(private key, public key)`.
pub fn generate_key_pair(kem: Kem) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
    let mut sk = Zeroizing::new(vec![0u8; kem.n_sk()]);
    OsRng.fill(&mut sk)?;
    let pk = public_key(kem, &sk)?;
    Ok((sk, pk))
}

/// Deterministic encapsulation. Returns `(shared_secret, enc)`.
pub fn encap_derand(
    kem: Kem,
    pk: &[u8],
    randomness: &[u8],
) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
    if randomness.len() != kem.n_random() {
        return Err(Error::length(
            "HPKE encapsulation randomness",
            kem.n_random(),
            randomness.len(),
        ));
    }
    if pk.len() != kem.n_pk() {
        return Err(Error::length("HPKE public key", kem.n_pk(), pk.len()));
    }
    let (enc, ss) = match kem {
        Kem::MlKem768 | Kem::MlKem1024 => {
            let m: &[u8; 32] = randomness.try_into().expect("length checked");
            let (ct, ss) = mlkem::encapsulate(kem.ml_level().expect("ML-KEM"), pk, m)?;
            (ct, ss.to_vec())
        }
        Kem::XWing => {
            let (ct, ss) =
                xwing::encapsulate_derand(pk, randomness.try_into().expect("length checked"))?;
            (ct, ss.to_vec())
        }
        Kem::MlKem1024P384 => {
            let (ct, ss) = mlkem1024_p384::encapsulate_derand(
                pk,
                randomness.try_into().expect("length checked"),
            )?;
            (ct, ss.to_vec())
        }
    };
    Ok((Zeroizing::new(ss), enc))
}

/// `Encap(pkR)`. Returns `(shared_secret, enc)`.
pub fn encap(kem: Kem, pk: &[u8]) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
    let mut r = Zeroizing::new(vec![0u8; kem.n_random()]);
    OsRng.fill(&mut r)?;
    encap_derand(kem, pk, &r)
}

/// `Decap(enc, skR)`.
pub fn decap(kem: Kem, enc: &[u8], sk: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if sk.len() != kem.n_sk() {
        return Err(Error::length("HPKE private key", kem.n_sk(), sk.len()));
    }
    if enc.len() != kem.n_enc() {
        return Err(Error::length("HPKE enc", kem.n_enc(), enc.len()));
    }
    let ss = match kem {
        Kem::MlKem768 | Kem::MlKem1024 => {
            let level = kem.ml_level().expect("ML-KEM");
            let kp = mlkem::keygen(level, sk.try_into().expect("length checked"));
            mlkem::decapsulate(level, &kp.decapsulation_key, enc)?.to_vec()
        }
        Kem::XWing => xwing::decapsulate_raw(sk.try_into().expect("length checked"), enc)?.to_vec(),
        Kem::MlKem1024P384 => {
            mlkem1024_p384::decapsulate_raw(sk.try_into().expect("length checked"), enc)?.to_vec()
        }
    };
    Ok(Zeroizing::new(ss))
}
