//! Keys and `AKP` COSE_Keys (draft-ietf-cose-dilithium): `pub` (-1) is the raw FIPS 204 public
//! key, `priv` (-2) the 32-byte seed from which the key pair is derived.

use std::fmt;

use vpqc_backend_libcrux::mldsa::{self, SEED_LEN, SIGN_RANDOMNESS_LEN};
use zeroize::Zeroizing;

use crate::cbor::{self, Value};
use crate::{Algorithm, Error, Result, canonical_map};

/// COSE_Key labels (RFC 9052 section 7.1, key type parameters from the IANA registry).
const KTY: i64 = 1;
const ALG: i64 = 3;
const KEY_OPS: i64 = 4;
const AKP_PUB: i64 = -1;
const AKP_PRIV: i64 = -2;
/// Key type `AKP` (algorithm key pair).
const KTY_AKP: i64 = 7;
/// `key_ops` values `sign` (1) and `verify` (2).
const OP_SIGN: i64 = 1;
const OP_VERIFY: i64 = 2;

/// A public key for verifying COSE signatures.
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

    /// Parse a public COSE_Key (optionally tagged 101). A key that carries private key material
    /// (`priv`) is rejected, so private keys are not accidentally handled as public ones.
    pub fn from_cose_key(bytes: &[u8]) -> Result<Self> {
        let map = parse(bytes)?;
        if map.get(AKP_PRIV).is_some() {
            return Err(Error::InvalidKey(
                "private key material in a public COSE_Key",
            ));
        }
        public_from(&map)
    }

    /// The public COSE_Key `{1: 7, 3: alg, -1: pub}`, deterministically encoded.
    pub fn to_cose_key(&self) -> Vec<u8> {
        cbor::encode(&canonical_map(vec![
            (Value::int(KTY), Value::int(KTY_AKP)),
            (Value::int(ALG), Value::int(self.alg.id())),
            (Value::int(AKP_PUB), Value::Bytes(self.public.clone())),
        ]))
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
            .finish_non_exhaustive()
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

    /// Parse a private COSE_Key. `pub` is required and must match the key derived from `priv`.
    pub fn from_cose_key(bytes: &[u8]) -> Result<Self> {
        let map = Zeroizing::new(parse(bytes)?);
        let public = public_from(&map)?;
        let seed: &[u8; SEED_LEN] = map
            .get(AKP_PRIV)
            .and_then(Value::as_bytes)
            .ok_or(Error::InvalidKey("missing priv"))?
            .try_into()
            .map_err(|_| Error::InvalidKey("priv must be a 32-byte seed"))?;
        let key = Self::from_seed(public.alg, seed);
        if key.public != public {
            return Err(Error::InvalidKey("pub does not match priv"));
        }
        Ok(key)
    }

    /// The private COSE_Key `{1: 7, 3: alg, -1: pub, -2: priv}`. Handle it like any private key.
    pub fn to_cose_key(&self) -> Zeroizing<Vec<u8>> {
        let map = Zeroizing::new(canonical_map(vec![
            (Value::int(KTY), Value::int(KTY_AKP)),
            (Value::int(ALG), Value::int(self.public.alg.id())),
            (
                Value::int(AKP_PUB),
                Value::Bytes(self.public.public.clone()),
            ),
            (Value::int(AKP_PRIV), Value::Bytes(self.seed.to_vec())),
        ]));
        Zeroizing::new(cbor::encode(&map))
    }

    /// The matching public key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.public.clone()
    }

    /// The algorithm this key is bound to.
    pub fn algorithm(&self) -> Algorithm {
        self.public.alg
    }

    /// Hedged ML-DSA signature with an empty context, as COSE requires.
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

impl zeroize::Zeroize for Value {
    fn zeroize(&mut self) {
        match self {
            Value::Bytes(b) => b.zeroize(),
            Value::Text(t) => t.zeroize(),
            Value::Array(items) => items.iter_mut().for_each(|i| i.zeroize()),
            Value::Map(entries) => entries.iter_mut().for_each(|(k, v)| {
                k.zeroize();
                v.zeroize();
            }),
            Value::Tag(_, inner) => inner.zeroize(),
            _ => {}
        }
    }
}

/// Decode a COSE_Key (tag 101 allowed) and apply the checks common to public and private keys.
fn parse(bytes: &[u8]) -> Result<Value> {
    let value = match cbor::decode(bytes)? {
        Value::Tag(101, inner) => *inner,
        other => other,
    };
    if !matches!(value, Value::Map(_)) {
        return Err(Error::Malformed("COSE_Key is not a map"));
    }
    if value.get(KTY).and_then(Value::as_i64) != Some(KTY_AKP) {
        return Err(Error::InvalidKey("kty must be AKP (7)"));
    }
    if let Some(ops) = value.get(KEY_OPS) {
        let ok = match ops {
            Value::Array(list) => list
                .iter()
                .all(|o| matches!(o.as_i64(), Some(OP_SIGN | OP_VERIFY))),
            _ => false,
        };
        if !ok {
            return Err(Error::InvalidKey(
                "key_ops must only contain sign and verify",
            ));
        }
    }
    Ok(value)
}

fn public_from(map: &Value) -> Result<VerifyingKey> {
    let alg = map
        .get(ALG)
        .ok_or(Error::InvalidKey("missing alg"))?
        .as_i64()
        .ok_or(Error::InvalidKey("alg must be an integer"))?;
    let public = map
        .get(AKP_PUB)
        .and_then(Value::as_bytes)
        .ok_or(Error::InvalidKey("missing pub"))?;
    VerifyingKey::from_bytes(Algorithm::from_id(alg)?, public)
}
