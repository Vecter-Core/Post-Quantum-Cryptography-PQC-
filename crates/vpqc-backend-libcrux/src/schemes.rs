use vpqc_core::{
    AlgorithmId, Error, Kem, KemId, KemKeyPair, PublicKey, RandomSource, Result, SecretKey,
    SharedSecret, SigId, SignatureScheme,
};

use crate::{mldsa, mlkem};

macro_rules! ml_kem_scheme {
    ($(#[$doc:meta])* $name:ident, $id:expr, $level:expr) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, Default)]
        pub struct $name;

        impl Kem for $name {
            fn id(&self) -> KemId {
                $id
            }

            fn public_key_len(&self) -> usize {
                $level.public_key_len()
            }

            fn ciphertext_len(&self) -> usize {
                $level.ciphertext_len()
            }

            fn generate(&self, rng: &mut dyn RandomSource) -> Result<KemKeyPair> {
                let mut seed = zeroize::Zeroizing::new([0u8; mlkem::SEED_LEN]);
                rng.fill(&mut *seed)?;
                let kp = mlkem::keygen($level, &seed);
                Ok(KemKeyPair {
                    public: PublicKey::new(AlgorithmId::Kem($id), kp.public),
                    secret: SecretKey::new(AlgorithmId::Kem($id), seed.to_vec()),
                })
            }

            fn encapsulate(
                &self,
                pk: &PublicKey,
                rng: &mut dyn RandomSource,
            ) -> Result<(Vec<u8>, SharedSecret)> {
                if pk.algorithm() != AlgorithmId::Kem($id) {
                    return Err(Error::AlgorithmMismatch);
                }
                let mut m = zeroize::Zeroizing::new([0u8; mlkem::ENCAPS_RANDOMNESS_LEN]);
                rng.fill(&mut *m)?;
                let (ct, ss) = mlkem::encapsulate($level, pk.as_bytes(), &m)?;
                Ok((ct, SharedSecret::new(*ss)))
            }

            fn decapsulate(&self, sk: &SecretKey, ciphertext: &[u8]) -> Result<SharedSecret> {
                if sk.algorithm() != AlgorithmId::Kem($id) {
                    return Err(Error::AlgorithmMismatch);
                }
                let seed: &[u8; mlkem::SEED_LEN] = sk
                    .expose_bytes()
                    .try_into()
                    .map_err(|_| Error::InvalidKey("bad ML-KEM secret key length"))?;
                let kp = mlkem::keygen($level, seed);
                let ss = mlkem::decapsulate($level, &kp.decapsulation_key, ciphertext)?;
                Ok(SharedSecret::new(*ss))
            }
        }
    };
}

ml_kem_scheme!(
    /// ML-KEM-768 (FIPS 203), NIST category 3.
    MlKem768, KemId::MlKem768, mlkem::Level::L768
);
ml_kem_scheme!(
    /// ML-KEM-1024 (FIPS 203), NIST category 5.
    MlKem1024, KemId::MlKem1024, mlkem::Level::L1024
);

macro_rules! ml_dsa_scheme {
    ($(#[$doc:meta])* $name:ident, $id:expr, $level:expr) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, Default)]
        pub struct $name;

        impl SignatureScheme for $name {
            fn id(&self) -> SigId {
                $id
            }

            fn signature_len(&self) -> usize {
                $level.signature_len()
            }

            fn generate(&self, rng: &mut dyn RandomSource) -> Result<(PublicKey, SecretKey)> {
                let mut seed = zeroize::Zeroizing::new([0u8; mldsa::SEED_LEN]);
                rng.fill(&mut *seed)?;
                let (vk, _sk) = mldsa::keygen($level, &seed);
                Ok((
                    PublicKey::new(AlgorithmId::Sig($id), vk),
                    SecretKey::new(AlgorithmId::Sig($id), seed.to_vec()),
                ))
            }

            fn sign(
                &self,
                sk: &SecretKey,
                message: &[u8],
                context: &[u8],
                rng: &mut dyn RandomSource,
            ) -> Result<Vec<u8>> {
                if sk.algorithm() != AlgorithmId::Sig($id) {
                    return Err(Error::AlgorithmMismatch);
                }
                let seed: &[u8; mldsa::SEED_LEN] = sk
                    .expose_bytes()
                    .try_into()
                    .map_err(|_| Error::InvalidKey("bad ML-DSA secret key length"))?;
                let (_vk, expanded) = mldsa::keygen($level, seed);
                let mut rnd = zeroize::Zeroizing::new([0u8; mldsa::SIGN_RANDOMNESS_LEN]);
                rng.fill(&mut *rnd)?;
                mldsa::sign($level, &expanded, message, context, &rnd)
            }

            fn verify(
                &self,
                pk: &PublicKey,
                message: &[u8],
                context: &[u8],
                signature: &[u8],
            ) -> Result<()> {
                if pk.algorithm() != AlgorithmId::Sig($id) {
                    return Err(Error::AlgorithmMismatch);
                }
                mldsa::verify($level, pk.as_bytes(), message, context, signature)
            }
        }
    };
}

ml_dsa_scheme!(
    /// ML-DSA-65 (FIPS 204), NIST category 3.
    MlDsa65, SigId::MlDsa65, mldsa::Level::L65
);
ml_dsa_scheme!(
    /// ML-DSA-87 (FIPS 204), NIST category 5.
    MlDsa87, SigId::MlDsa87, mldsa::Level::L87
);
