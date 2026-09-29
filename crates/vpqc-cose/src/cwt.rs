//! CBOR Web Tokens (RFC 8392): claims in a `COSE_Sign1`, with the same checks as `vpqc-jose`'s
//! JWT validation (RFC 8725 in spirit): `exp` required by default, `nbf`, issuer, and an
//! audience rule where a token carrying `aud` is only accepted by a verifier that states its
//! own audience.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::cbor::{self, Value};
use crate::sign1::{self, Headers};
use crate::{Error, Result, SigningKey, VerifyingKey, canonical_map};

/// CBOR tag of a CWT (RFC 8392 section 6), optional around the `COSE_Sign1`.
pub const TAG: u64 = 61;

const ISS: i64 = 1;
const SUB: i64 = 2;
const AUD: i64 = 3;
const EXP: i64 = 4;
const NBF: i64 = 5;
const IAT: i64 = 6;
const CTI: i64 = 7;

/// CWT claims. Times are seconds since the Unix epoch.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Claims {
    /// Issuer (1).
    pub iss: Option<String>,
    /// Subject (2).
    pub sub: Option<String>,
    /// Audience (3). Decoding also accepts an array of strings; see [`Validation::audience`].
    pub aud: Option<String>,
    /// Expiration time (4).
    pub exp: Option<i64>,
    /// Not before (5).
    pub nbf: Option<i64>,
    /// Issued at (6).
    pub iat: Option<i64>,
    /// CWT ID (7).
    pub cti: Option<Vec<u8>>,
    /// Other claims (keys other than 1 to 7), in encoded key order.
    pub other: Vec<(Value, Value)>,
}

/// Claim checks for [`decode`].
#[derive(Debug, Clone)]
pub struct Validation {
    /// Allowed clock skew in seconds for `exp` and `nbf`. Default 60.
    pub leeway: u64,
    /// Reject tokens without `exp`. Default true.
    pub require_exp: bool,
    /// Required `iss`, if set.
    pub issuer: Option<String>,
    /// This service's identifier. A token with an `aud` claim is accepted only if `aud` is (or,
    /// as an array, contains) it, so a token with `aud` and no configured audience is rejected.
    pub audience: Option<String>,
    /// Authenticated data bound to the token but not carried in it (`external_aad`).
    pub external_aad: Vec<u8>,
    /// The current time in seconds since the Unix epoch; the system clock if unset.
    pub now: Option<i64>,
}

impl Default for Validation {
    fn default() -> Self {
        Validation {
            leeway: 60,
            require_exp: true,
            issuer: None,
            audience: None,
            external_aad: Vec::new(),
            now: None,
        }
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl Claims {
    fn to_cbor(&self) -> Result<Vec<u8>> {
        let mut entries = Vec::new();
        let mut text = |label, v: &Option<String>| {
            if let Some(t) = v {
                entries.push((Value::int(label), Value::Text(t.clone())));
            }
        };
        text(ISS, &self.iss);
        text(SUB, &self.sub);
        text(AUD, &self.aud);
        for (label, t) in [(EXP, self.exp), (NBF, self.nbf), (IAT, self.iat)] {
            if let Some(t) = t {
                entries.push((Value::int(label), Value::int(t)));
            }
        }
        if let Some(cti) = &self.cti {
            entries.push((Value::int(CTI), Value::Bytes(cti.clone())));
        }
        for (k, v) in &self.other {
            if k.as_i64().is_some_and(|l| (ISS..=CTI).contains(&l)) {
                return Err(Error::Malformed("registered claim in Claims::other"));
            }
            if !matches!(k, Value::Uint(_) | Value::Nint(_) | Value::Text(_)) {
                return Err(Error::Malformed("claim key must be an integer or text"));
            }
            entries.push((k.clone(), v.clone()));
        }
        let map = canonical_map(entries);
        if let Value::Map(e) = &map {
            if e.windows(2).any(|w| w[0].0 == w[1].0) {
                return Err(Error::Malformed("duplicate claim"));
            }
        }
        Ok(cbor::encode(&map))
    }

    fn from_cbor(bytes: &[u8]) -> Result<(Self, Vec<String>)> {
        let Value::Map(entries) = cbor::decode(bytes)? else {
            return Err(Error::Malformed("CWT claims are not a map"));
        };
        let mut c = Claims::default();
        let mut audiences = Vec::new();
        for (k, v) in entries {
            let text = |name| {
                v.as_text()
                    .map(str::to_owned)
                    .ok_or(Error::InvalidClaim(name))
            };
            // NumericDate: an integer, or a float (fraction dropped towards -infinity).
            let time = |name| match &v {
                Value::Float(f) if f.is_finite() && f.abs() < 1e15 => Ok(f.floor() as i64),
                other => other.as_i64().ok_or(Error::InvalidClaim(name)),
            };
            match k.as_i64() {
                Some(ISS) => c.iss = Some(text("iss")?),
                Some(SUB) => c.sub = Some(text("sub")?),
                Some(AUD) => match &v {
                    Value::Text(t) => {
                        c.aud = Some(t.clone());
                        audiences.push(t.clone());
                    }
                    Value::Array(list) if !list.is_empty() => {
                        for a in list {
                            audiences
                                .push(a.as_text().ok_or(Error::InvalidClaim("aud"))?.to_owned());
                        }
                    }
                    _ => return Err(Error::InvalidClaim("aud")),
                },
                Some(EXP) => c.exp = Some(time("exp")?),
                Some(NBF) => c.nbf = Some(time("nbf")?),
                Some(IAT) => c.iat = Some(time("iat")?),
                Some(CTI) => c.cti = Some(v.as_bytes().ok_or(Error::InvalidClaim("cti"))?.to_vec()),
                _ => c.other.push((k, v)),
            }
        }
        Ok((c, audiences))
    }
}

/// Sign `claims` as a CWT valid for `ttl` seconds: sets `iat` and `exp` (replacing any given).
pub fn encode(key: &SigningKey, mut claims: Claims, ttl: u64) -> Result<Vec<u8>> {
    let iat = now();
    claims.iat = Some(iat);
    claims.exp = Some(iat.saturating_add(i64::try_from(ttl).unwrap_or(i64::MAX)));
    encode_with(key, &claims, &Headers::default(), &[])
}

/// Sign `claims` exactly as given, with extra protected headers (e.g. `kid`) and external AAD.
/// The result is a tagged `COSE_Sign1` (tag 18), not wrapped in the optional CWT tag.
pub fn encode_with(
    key: &SigningKey,
    claims: &Claims,
    headers: &Headers,
    external_aad: &[u8],
) -> Result<Vec<u8>> {
    sign1::sign(key, &claims.to_cbor()?, headers, external_aad)
}

/// Verify a CWT (tag 61 optional) and check its claims; returns the claims.
pub fn decode(token: &[u8], key: &VerifyingKey, v: &Validation) -> Result<Claims> {
    let value = match cbor::decode(token)? {
        Value::Tag(TAG, inner) => *inner,
        other => other,
    };
    let verified = sign1::verify_inner(&value, key, &v.external_aad, None)?;
    let (claims, audiences) = Claims::from_cbor(&verified.payload)?;
    let now = v.now.unwrap_or_else(now);
    let leeway = i64::try_from(v.leeway).unwrap_or(i64::MAX);
    match claims.exp {
        Some(exp) if now >= exp.saturating_add(leeway) => return Err(Error::InvalidClaim("exp")),
        None if v.require_exp => return Err(Error::InvalidClaim("exp")),
        _ => {}
    }
    if claims
        .nbf
        .is_some_and(|nbf| now.saturating_add(leeway) < nbf)
    {
        return Err(Error::InvalidClaim("nbf"));
    }
    if let Some(iss) = &v.issuer {
        if claims.iss.as_ref() != Some(iss) {
            return Err(Error::InvalidClaim("iss"));
        }
    }
    match &v.audience {
        _ if audiences.is_empty() && v.audience.is_none() => {}
        Some(me) if audiences.iter().any(|a| a == me) => {}
        _ => return Err(Error::InvalidClaim("aud")),
    }
    Ok(claims)
}
