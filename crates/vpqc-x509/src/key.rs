//! ML-DSA keys in the standard X.509 encodings (RFC 9881): SubjectPublicKeyInfo with the raw
//! public key, and PKCS#8 whose private key is the 32-byte seed.

use std::fmt;

use vpqc_backend_libcrux::mldsa::{self, SEED_LEN, SIGN_RANDOMNESS_LEN};
use zeroize::Zeroizing;

use crate::der::{self, seq};
use crate::{Algorithm, Error, Result, pem};

/// An ML-DSA public key.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey {
    alg: Algorithm,
    raw: Vec<u8>,
}

/// An ML-DSA private key (seed and expanded key, zeroized on drop).
pub struct PrivateKey {
    seed: Zeroizing<[u8; SEED_LEN]>,
    expanded: Zeroizing<Vec<u8>>,
    public: PublicKey,
}

impl PublicKey {
    /// A key from its raw FIPS 204 encoding.
    pub fn from_raw(alg: Algorithm, raw: &[u8]) -> Result<Self> {
        if raw.len() != alg.level().public_key_len() {
            return Err(Error::InvalidKey(
                "public key length does not match the algorithm",
            ));
        }
        Ok(PublicKey {
            alg,
            raw: raw.to_vec(),
        })
    }

    /// DER `SubjectPublicKeyInfo`.
    pub fn to_spki_der(&self) -> Vec<u8> {
        seq(&[&self.alg.algorithm_identifier(), &der::bits(0, &self.raw)])
    }

    /// PEM `PUBLIC KEY`.
    pub fn to_spki_pem(&self) -> String {
        pem::encode("PUBLIC KEY", &self.to_spki_der())
    }

    /// Parse a DER `SubjectPublicKeyInfo` (ML-DSA-65 or ML-DSA-87).
    pub fn from_spki_der(der: &[u8]) -> Result<Self> {
        use x509_parser::prelude::FromDer;
        let (rest, spki) = x509_parser::x509::SubjectPublicKeyInfo::from_der(der)?;
        if !rest.is_empty() {
            return Err(Error::Malformed("trailing data after SubjectPublicKeyInfo"));
        }
        Self::from_parsed(&spki)
    }

    /// Parse a PEM `PUBLIC KEY`.
    pub fn from_spki_pem(pem_text: &str) -> Result<Self> {
        Self::from_spki_der(&pem::decode("PUBLIC KEY", pem_text)?)
    }

    pub(crate) fn from_parsed(spki: &x509_parser::x509::SubjectPublicKeyInfo<'_>) -> Result<Self> {
        let alg = Algorithm::from_identifier(&spki.algorithm)?;
        if spki.subject_public_key.unused_bits != 0 {
            return Err(Error::Malformed("public key BIT STRING has unused bits"));
        }
        Self::from_raw(alg, &spki.subject_public_key.data)
    }

    /// The algorithm.
    pub fn algorithm(&self) -> Algorithm {
        self.alg
    }

    /// The raw public key.
    pub fn as_raw(&self) -> &[u8] {
        &self.raw
    }

    /// Verify a pure ML-DSA signature with an empty context (as X.509 uses).
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        mldsa::verify(self.alg.level(), &self.raw, message, b"", signature)
            .map_err(|_| Error::BadSignature)
    }

    /// Subject key identifier: the first 20 bytes of SHA-256 over the public key
    /// (RFC 7093 section 2, method 1).
    pub fn key_identifier(&self) -> [u8; 20] {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(&self.raw);
        digest[..20].try_into().expect("32 >= 20")
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicKey")
            .field("alg", &self.alg)
            .field(
                "key_id",
                &self
                    .key_identifier()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>(),
            )
            .finish()
    }
}

impl PrivateKey {
    /// A fresh key from the operating system RNG.
    pub fn generate(alg: Algorithm) -> Result<Self> {
        let mut seed = Zeroizing::new([0u8; SEED_LEN]);
        getrandom::fill(&mut *seed).map_err(|_| Error::Rng)?;
        Ok(Self::from_seed(alg, &seed))
    }

    /// The key pair derived from a 32-byte seed (FIPS 204 `ML-DSA.KeyGen_internal`).
    pub fn from_seed(alg: Algorithm, seed: &[u8; SEED_LEN]) -> Self {
        let (public, expanded) = mldsa::keygen(alg.level(), seed);
        PrivateKey {
            seed: Zeroizing::new(*seed),
            expanded,
            public: PublicKey { alg, raw: public },
        }
    }

    /// The matching public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// The algorithm.
    pub fn algorithm(&self) -> Algorithm {
        self.public.alg
    }

    /// Hedged pure ML-DSA signature with an empty context.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let mut rnd = Zeroizing::new([0u8; SIGN_RANDOMNESS_LEN]);
        getrandom::fill(&mut *rnd).map_err(|_| Error::Rng)?;
        mldsa::sign(self.public.alg.level(), &self.expanded, message, b"", &rnd)
            .map_err(|_| Error::InvalidKey("signing failed"))
    }

    /// DER PKCS#8 `OneAsymmetricKey` in the seed-only form (RFC 9881 recommends it).
    pub fn to_pkcs8_der(&self) -> Zeroizing<Vec<u8>> {
        let private = Zeroizing::new(der::implicit(0, &*self.seed));
        Zeroizing::new(seq(&[
            &der::uint(&[0]),
            &self.public.alg.algorithm_identifier(),
            &der::octets(&private),
        ]))
    }

    /// PEM `PRIVATE KEY` (seed-only form).
    pub fn to_pkcs8_pem(&self) -> Zeroizing<String> {
        Zeroizing::new(pem::encode("PRIVATE KEY", &self.to_pkcs8_der()))
    }

    /// Parse DER PKCS#8. Accepts the `seed` and `both` forms of RFC 9881; for `both`, the
    /// expanded key must match the one derived from the seed. The `expandedKey`-only form is
    /// rejected: without the seed the key cannot be checked or exported in the recommended form.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        let (alg, private) = crate::parse::pkcs8(der)?;
        let (seed, expanded) = crate::parse::ml_dsa_private_key(&private)?;
        let seed: &[u8; SEED_LEN] = seed
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidKey("seed must be 32 bytes"))?;
        let key = Self::from_seed(alg, seed);
        if let Some(expanded) = expanded {
            use subtle::ConstantTimeEq;
            if !bool::from(expanded.as_slice().ct_eq(key.expanded.as_slice())) {
                return Err(Error::InvalidKey("expanded key does not match the seed"));
            }
        }
        Ok(key)
    }

    /// Parse PEM `PRIVATE KEY`.
    pub fn from_pkcs8_pem(pem_text: &str) -> Result<Self> {
        let der = Zeroizing::new(pem::decode("PRIVATE KEY", pem_text)?);
        Self::from_pkcs8_der(&der)
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}
