//! Byte-level ML-KEM primitives with explicit randomness.

use vpqc_core::{Error, Result};
use zeroize::Zeroizing;

/// Length of a key-generation seed `d || z`.
pub const SEED_LEN: usize = 64;
/// Length of the encapsulation randomness `m`.
pub const ENCAPS_RANDOMNESS_LEN: usize = 32;
/// Length of the shared secret.
pub const SHARED_SECRET_LEN: usize = 32;

/// ML-KEM parameter set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// ML-KEM-768.
    L768,
    /// ML-KEM-1024.
    L1024,
}

impl Level {
    /// Encapsulation key length.
    pub const fn public_key_len(self) -> usize {
        match self {
            Level::L768 => 1184,
            Level::L1024 => 1568,
        }
    }

    /// Ciphertext length.
    pub const fn ciphertext_len(self) -> usize {
        match self {
            Level::L768 => 1088,
            Level::L1024 => 1568,
        }
    }

    const fn decapsulation_key_len(self) -> usize {
        match self {
            Level::L768 => 2400,
            Level::L1024 => 3168,
        }
    }
}

/// An expanded ML-KEM key pair derived from a seed.
pub struct KeyPair {
    /// Encapsulation key (public).
    pub public: Vec<u8>,
    /// Expanded decapsulation key (secret; zeroized on drop).
    pub decapsulation_key: Zeroizing<Vec<u8>>,
}

macro_rules! level_fns {
    ($keygen:ident, $encaps:ident, $decaps:ident, $m:ident, $Pk:ident, $Sk:ident, $Ct:ident) => {
        fn $keygen(seed: [u8; SEED_LEN]) -> KeyPair {
            let kp = libcrux_ml_kem::$m::generate_key_pair(seed);
            KeyPair {
                public: kp.pk().to_vec(),
                decapsulation_key: Zeroizing::new(kp.sk().to_vec()),
            }
        }

        fn $encaps(pk: &[u8], m: [u8; ENCAPS_RANDOMNESS_LEN]) -> Result<(Vec<u8>, [u8; 32])> {
            let pk: libcrux_ml_kem::$m::$Pk = pk
                .try_into()
                .map_err(|_| Error::InvalidKey("bad ML-KEM public key length"))?;
            // FIPS 203 section 7.2 encapsulation key check.
            if !libcrux_ml_kem::$m::validate_public_key(&pk) {
                return Err(Error::InvalidKey("ML-KEM public key failed validation"));
            }
            let (ct, ss) = libcrux_ml_kem::$m::encapsulate(&pk, m);
            Ok((ct.as_slice().to_vec(), ss))
        }

        fn $decaps(dk: &[u8], ct: &[u8]) -> Result<[u8; 32]> {
            let sk: libcrux_ml_kem::$m::$Sk = dk
                .try_into()
                .map_err(|_| Error::InvalidKey("bad ML-KEM decapsulation key"))?;
            let ct: libcrux_ml_kem::$m::$Ct = ct
                .try_into()
                .map_err(|_| Error::Backend("bad ML-KEM ciphertext"))?;
            Ok(libcrux_ml_kem::$m::decapsulate(&sk, &ct))
        }
    };
}

level_fns!(
    keygen_768,
    encaps_768,
    decaps_768,
    mlkem768,
    MlKem768PublicKey,
    MlKem768PrivateKey,
    MlKem768Ciphertext
);
level_fns!(
    keygen_1024,
    encaps_1024,
    decaps_1024,
    mlkem1024,
    MlKem1024PublicKey,
    MlKem1024PrivateKey,
    MlKem1024Ciphertext
);

/// Deterministic key generation from the 64-byte seed `d || z` (FIPS 203 `KeyGen_internal`).
pub fn keygen(level: Level, seed: &[u8; SEED_LEN]) -> KeyPair {
    match level {
        Level::L768 => keygen_768(*seed),
        Level::L1024 => keygen_1024(*seed),
    }
}

/// Deterministic encapsulation with randomness `m` (FIPS 203 `Encaps_internal`).
///
/// Performs the encapsulation-key check first. Returns `(ciphertext, shared_secret)`.
pub fn encapsulate(
    level: Level,
    pk: &[u8],
    m: &[u8; ENCAPS_RANDOMNESS_LEN],
) -> Result<(Vec<u8>, Zeroizing<[u8; SHARED_SECRET_LEN]>)> {
    if pk.len() != level.public_key_len() {
        return Err(Error::length(
            "ML-KEM public key",
            level.public_key_len(),
            pk.len(),
        ));
    }
    let (ct, ss) = match level {
        Level::L768 => encaps_768(pk, *m)?,
        Level::L1024 => encaps_1024(pk, *m)?,
    };
    Ok((ct, Zeroizing::new(ss)))
}

/// Decapsulate with an expanded decapsulation key. Implicit rejection applies.
pub fn decapsulate(
    level: Level,
    decapsulation_key: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<[u8; SHARED_SECRET_LEN]>> {
    if decapsulation_key.len() != level.decapsulation_key_len() {
        return Err(Error::length(
            "ML-KEM decapsulation key",
            level.decapsulation_key_len(),
            decapsulation_key.len(),
        ));
    }
    if ciphertext.len() != level.ciphertext_len() {
        return Err(Error::length(
            "ML-KEM ciphertext",
            level.ciphertext_len(),
            ciphertext.len(),
        ));
    }
    let ss = match level {
        Level::L768 => decaps_768(decapsulation_key, ciphertext)?,
        Level::L1024 => decaps_1024(decapsulation_key, ciphertext)?,
    };
    Ok(Zeroizing::new(ss))
}
