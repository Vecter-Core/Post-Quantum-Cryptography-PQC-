//! JWS compact serialization (RFC 7515) with ML-DSA.

use serde_json::{Map, Value};

use crate::{Algorithm, Error, Result, SigningKey, VerifyingKey, b64, json};

/// Tokens longer than this are rejected before any parsing (1 MiB).
pub const MAX_TOKEN_LEN: usize = 1 << 20;

/// A verified JWS.
#[derive(Debug, Clone)]
pub struct Verified {
    /// The protected header.
    pub header: Map<String, Value>,
    /// The payload.
    pub payload: Vec<u8>,
}

/// Sign `payload` into a compact JWS. `header` may add parameters such as `kid`, `typ` or
/// `cty`; `alg` is set from the key, and `crit` / `b64` are not supported.
pub fn sign(key: &SigningKey, payload: &[u8], header: &Map<String, Value>) -> Result<String> {
    if ["alg", "crit", "b64"]
        .iter()
        .any(|p| header.contains_key(*p))
    {
        return Err(Error::Malformed(
            "header: alg is set from the key; crit and b64 are unsupported",
        ));
    }
    let mut full = header.clone();
    full.insert("alg".into(), key.algorithm().name().into());
    let header_json = serde_json::to_vec(&full).map_err(|_| Error::Malformed("header"))?;
    let mut token = b64::encode(&header_json);
    token.push('.');
    token.push_str(&b64::encode(payload));
    let signature = key.sign(token.as_bytes())?;
    token.push('.');
    token.push_str(&b64::encode(&signature));
    Ok(token)
}

/// Verify a compact JWS with `key` and return its header and payload.
///
/// The header's `alg` must name the key's algorithm (so `none` and algorithm substitution are
/// rejected), header members must be unique, and any `crit` parameter is rejected because no
/// extensions are implemented.
pub fn verify(token: &str, key: &VerifyingKey) -> Result<Verified> {
    let (header, signing_input, signature) = split(token)?;
    let alg = header
        .get("alg")
        .and_then(Value::as_str)
        .ok_or(Error::Malformed("header: missing alg"))?;
    if Algorithm::from_name(alg)? != key.algorithm() {
        return Err(Error::AlgorithmMismatch);
    }
    if header.contains_key("crit") {
        return Err(Error::UnsupportedCritical);
    }
    if header.get("b64").is_some_and(|v| v != true) {
        return Err(Error::UnsupportedCritical);
    }
    let signature = b64::decode(signature, "signature")?;
    key.verify(signing_input.as_bytes(), &signature)?;
    let payload_b64 = &signing_input[signing_input.find('.').expect("checked by split") + 1..];
    let payload = b64::decode(payload_b64, "payload")?;
    Ok(Verified { header, payload })
}

/// The protected header, **unverified**. Use it only to choose a key (for example by `kid`),
/// then call [`verify`].
pub fn decode_header(token: &str) -> Result<Map<String, Value>> {
    split(token).map(|(header, _, _)| header)
}

/// `(header, signing input, encoded signature)`.
fn split(token: &str) -> Result<(Map<String, Value>, &str, &str)> {
    if token.len() > MAX_TOKEN_LEN {
        return Err(Error::Malformed("token: too long"));
    }
    let mut parts = token.split('.');
    let (Some(h), Some(_), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Error::Malformed(
            "token: expected three dot-separated parts",
        ));
    };
    let header = json::object(&b64::decode(h, "header")?, "header")?;
    let signing_input = &token[..token.len() - s.len() - 1];
    Ok((header, signing_input, s))
}
