//! Keys and `AKP` JWKs (draft-ietf-cose-dilithium): `pub` is the raw FIPS 204 public key,
//! `priv` the 32-byte seed from which the key pair is derived.

use std::fmt;

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use vpqc_backend_libcrux::mldsa::{self, SEED_LEN, SIGN_RANDOMNESS_LEN};
use zeroize::Zeroizing;

use crate::{Algorithm, Error, Result, b64, json};

/// A public key for verifying JWS signatures.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifyingKey {
    alg: Algorithm,
    public: Vec<u8>,
}

/// A private key for signing. The seed and expanded key are zeroized on drop.
pub struct SigningKey {
    seed: Zeroizing<[u8; SEED_LEN]>,
    expanded: Zeroizing<Vec<u8>>,
    public: VerifyingKey,
}

impl VerifyingKey {
    /// A key from its raw public key bytes.
    pub fn from_bytes(alg: Algorithm, public: &[u8]) -> Result<Self> {
        if public.len() != alg.public_key_len() {
            return Err(Error::InvalidKey("public key length does not match alg"));
        }
        Ok(VerifyingKey {
            alg,
            public: public.to_vec(),
        })
    }

    /// Parse a public `AKP` JWK. A JWK that carries private key material (`priv`) is rejected,
    /// so private keys are not accidentally handled as public ones.
    pub fn from_jwk(jwk: &str) -> Result<Self> {
        let (key, members) = parse(jwk)?;
        if members.contains_key("priv") {
            return Err(Error::InvalidKey("private key material in a public JWK"));
        }
        Ok(key)
    }

    /// The public JWK: `{"alg":…,"kty":"AKP","pub":…}`.
    pub fn to_jwk(&self) -> String {
        self.canonical_jwk()
    }

    /// The RFC 7638 JWK thumbprint (SHA-256, base64url), usable as a `kid`.
    pub fn thumbprint(&self) -> String {
        b64::encode(&Sha256::digest(self.canonical_jwk().as_bytes()))
    }

    /// Required members in lexicographic order without whitespace (RFC 7638 section 3).
    fn canonical_jwk(&self) -> String {
        format!(
            r#"{{"alg":"{}","kty":"AKP","pub":"{}"}}"#,
            self.alg.name(),
            b64::encode(&self.public)
        )
    }

    /// The algorithm this key is bound to.
    pub fn algorithm(&self) -> Algorithm {
        self.alg
    }

    /// The raw public key.
    pub fn as_bytes(&self) -> &[u8] {
        &self.public
    }

    pub(crate) fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        if signature.len() != self.alg.signature_len() {
            return Err(Error::VerificationFailed);
        }
        mldsa::verify(self.alg.level(), &self.public, message, b"", signature)
            .map_err(|_| Error::VerificationFailed)
    }
}

impl fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifyingKey")
            .field("alg", &self.alg)
            .field("thumbprint", &self.thumbprint())
            .finish()
    }
}

impl SigningKey {
    /// A fresh key from the operating system RNG.
    pub fn generate(alg: Algorithm) -> Result<Self> {
        let mut seed = Zeroizing::new([0u8; SEED_LEN]);
        getrandom::fill(&mut *seed).map_err(|_| Error::Rng)?;
        Ok(Self::from_seed(alg, &seed))
    }

    /// The key pair derived from a 32-byte seed (FIPS 204 `ML-DSA.KeyGen_internal`).
    pub fn from_seed(alg: Algorithm, seed: &[u8; SEED_LEN]) -> Self {
        let (public, expanded) = mldsa::keygen(alg.level(), seed);
        SigningKey {
            seed: Zeroizing::new(*seed),
            expanded,
            public: VerifyingKey { alg, public },
        }
    }

    /// Parse a private `AKP` JWK. `pub` is required and must match the key derived from
    /// `priv`.
    pub fn from_jwk(jwk: &str) -> Result<Self> {
        let (public, members) = parse(jwk)?;
        let encoded = members
            .get("priv")
            .and_then(Value::as_str)
            .ok_or(Error::InvalidKey("missing priv"))?;
        let bytes = Zeroizing::new(b64::decode(encoded, "JWK priv")?);
        let seed: &[u8; SEED_LEN] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidKey("priv must be a 32-byte seed"))?;
        let key = Self::from_seed(public.alg, seed);
        if key.public != public {
            return Err(Error::InvalidKey("pub does not match priv"));
        }
        Ok(key)
    }

    /// The private JWK, including `priv`. Handle it like any private key.
    pub fn to_jwk(&self) -> String {
        format!(
            r#"{{"alg":"{}","kty":"AKP","priv":"{}","pub":"{}"}}"#,
            self.public.alg.name(),
            b64::encode(&*self.seed),
            b64::encode(&self.public.public)
        )
    }

    /// The matching public key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.public.clone()
    }

    /// The algorithm this key is bound to.
    pub fn algorithm(&self) -> Algorithm {
        self.public.alg
    }

    /// Hedged ML-DSA signature with an empty context, as JOSE requires.
    pub(crate) fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let mut rnd = Zeroizing::new([0u8; SIGN_RANDOMNESS_LEN]);
        getrandom::fill(&mut *rnd).map_err(|_| Error::Rng)?;
        mldsa::sign(self.public.alg.level(), &self.expanded, message, b"", &rnd)
            .map_err(|_| Error::InvalidKey("signing failed"))
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

/// Common JWK checks; returns the public key and the members.
fn parse(jwk: &str) -> Result<(VerifyingKey, Map<String, Value>)> {
    let members = json::object(jwk.as_bytes(), "JWK")?;
    let text = |name: &'static str| members.get(name).and_then(Value::as_str);
    if text("kty") != Some("AKP") {
        return Err(Error::InvalidKey("kty must be AKP"));
    }
    let alg = Algorithm::from_name(text("alg").ok_or(Error::InvalidKey("missing alg"))?)?;
    if members.get("use").is_some_and(|u| u != "sig") {
        return Err(Error::InvalidKey("use must be sig"));
    }
    if let Some(ops) = members.get("key_ops") {
        let ok = ops
            .as_array()
            .is_some_and(|a| a.iter().all(|o| o == "sign" || o == "verify"));
        if !ok {
            return Err(Error::InvalidKey(
                "key_ops must only contain sign and verify",
            ));
        }
    }
    let public = b64::decode(
        text("pub").ok_or(Error::InvalidKey("missing pub"))?,
        "JWK pub",
    )?;
    Ok((VerifyingKey::from_bytes(alg, &public)?, members))
}
