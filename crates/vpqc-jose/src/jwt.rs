//! JSON Web Tokens (RFC 7519) with the checks recommended by RFC 8725.

use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};

use crate::{Error, Result, SigningKey, VerifyingKey, json, jws};

/// Claim checks for [`decode`].
#[derive(Debug, Clone)]
pub struct Validation {
    /// Allowed clock skew in seconds for `exp` and `nbf`. Default 60.
    pub leeway: u64,
    /// Reject tokens without `exp`. Default true.
    pub require_exp: bool,
    /// Required `iss`, if set.
    pub issuer: Option<String>,
    /// This service's identifier. A token with an `aud` claim is accepted only if `aud`
    /// contains it (RFC 7519 section 4.1.3), so a token with `aud` and no configured audience is
    /// rejected.
    pub audience: Option<String>,
    /// Required header `typ` (compared case-insensitively), for explicit typing (RFC 8725
    /// section 3.11), e.g. `at+jwt`. If unset, a present `typ` must be `JWT`.
    pub typ: Option<String>,
    /// The current time in seconds since the Unix epoch; the system clock if unset.
    pub now: Option<u64>,
}

impl Default for Validation {
    fn default() -> Self {
        Validation {
            leeway: 60,
            require_exp: true,
            issuer: None,
            audience: None,
            typ: None,
            now: None,
        }
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Sign `claims` as a JWT valid for `ttl` seconds: sets `iat` and `exp` (replacing any given),
/// and the header `typ: JWT` and `kid` (the key's RFC 7638 thumbprint).
pub fn encode(key: &SigningKey, mut claims: Map<String, Value>, ttl: u64) -> Result<String> {
    let iat = now();
    claims.insert("iat".into(), iat.into());
    claims.insert("exp".into(), iat.saturating_add(ttl).into());
    let mut header = Map::new();
    header.insert("typ".into(), "JWT".into());
    header.insert("kid".into(), key.verifying_key().thumbprint().into());
    encode_with_header(key, &claims, &header)
}

/// Sign `claims` exactly as given, with extra header parameters (see [`jws::sign`]).
pub fn encode_with_header(
    key: &SigningKey,
    claims: &Map<String, Value>,
    header: &Map<String, Value>,
) -> Result<String> {
    let payload = serde_json::to_vec(claims).map_err(|_| Error::Malformed("claims"))?;
    jws::sign(key, &payload, header)
}

/// Verify a JWT and check its claims; returns the claims.
pub fn decode(token: &str, key: &VerifyingKey, v: &Validation) -> Result<Map<String, Value>> {
    let verified = jws::verify(token, key)?;
    let typ = verified.header.get("typ");
    let expected_typ = v.typ.as_deref().unwrap_or("JWT");
    match typ {
        Some(Value::String(t)) if t.eq_ignore_ascii_case(expected_typ) => {}
        None if v.typ.is_none() => {}
        _ => return Err(Error::InvalidClaim("typ")),
    }
    let claims = json::object(&verified.payload, "claims")?;
    let now = v.now.unwrap_or_else(now);
    let time = |name: &'static str| -> Result<Option<f64>> {
        match claims.get(name) {
            None => Ok(None),
            Some(value) => value.as_f64().map(Some).ok_or(Error::InvalidClaim(name)),
        }
    };
    let (now_f, leeway) = (now as f64, v.leeway as f64);
    match time("exp")? {
        Some(exp) if now_f >= exp + leeway => return Err(Error::InvalidClaim("exp")),
        None if v.require_exp => return Err(Error::InvalidClaim("exp")),
        _ => {}
    }
    if time("nbf")?.is_some_and(|nbf| now_f + leeway < nbf) {
        return Err(Error::InvalidClaim("nbf"));
    }
    time("iat")?;
    if let Some(iss) = &v.issuer {
        if claims.get("iss").and_then(Value::as_str) != Some(iss) {
            return Err(Error::InvalidClaim("iss"));
        }
    }
    if let Some(aud) = claims.get("aud") {
        let listed = |me: &str| match aud {
            Value::String(a) => a == me,
            Value::Array(list) => list.iter().any(|a| a == me),
            _ => false,
        };
        if !v.audience.as_deref().is_some_and(listed) {
            return Err(Error::InvalidClaim("aud"));
        }
    } else if v.audience.is_some() {
        return Err(Error::InvalidClaim("aud"));
    }
    Ok(claims)
}
