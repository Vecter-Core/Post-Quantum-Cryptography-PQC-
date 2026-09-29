//! `COSE_Sign1` (RFC 9052 section 4.2): one signer, payload attached or detached.
//!
//! Signing puts `alg` (1), `content type` (3) and `kid` (4) in the protected header, so all of
//! them are covered by the signature, and writes the message with tag 18.
//!
//! Verification requires `alg` in the protected header, equal to the key's algorithm (no
//! algorithm substitution), and rejects:
//! * a `crit` parameter (none are implemented);
//! * a label present in both the protected and the unprotected header (RFC 9052 section 3);
//! * a wrong signature length and, of course, a signature that does not verify over the
//!   `Sig_structure` with the given external AAD.

use crate::cbor::{self, Value};
use crate::{Algorithm, Error, Result, SigningKey, VerifyingKey, canonical_map};

/// CBOR tag of `COSE_Sign1`.
pub const TAG: u64 = 18;

const ALG: i64 = 1;
const CRIT: i64 = 2;
const CONTENT_TYPE: i64 = 3;
const KID: i64 = 4;

/// The `content type` header parameter: a CoAP Content-Format number or a media type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContentType {
    /// CoAP Content-Format (e.g. 60 for `application/cbor`).
    Format(u64),
    /// Media type text, e.g. `application/json`.
    MediaType(String),
}

/// Optional header parameters for [`sign`] and [`sign_detached`]; both go in the protected
/// header.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Headers {
    /// Key identifier.
    pub kid: Option<Vec<u8>>,
    /// Content type of the payload.
    pub content_type: Option<ContentType>,
}

/// A verified message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    /// The payload (for detached messages, the one passed in).
    pub payload: Vec<u8>,
    /// The header parameters (`kid` from either header bucket; only a protected one is signed).
    pub headers: Headers,
    /// Whether the `kid` came from the protected header.
    pub kid_protected: bool,
}

fn protected_header(alg: Algorithm, headers: &Headers) -> Vec<u8> {
    let mut entries = vec![(Value::int(ALG), Value::int(alg.id()))];
    if let Some(ct) = &headers.content_type {
        let v = match ct {
            ContentType::Format(n) => Value::Uint(*n),
            ContentType::MediaType(t) => Value::Text(t.clone()),
        };
        entries.push((Value::int(CONTENT_TYPE), v));
    }
    if let Some(kid) = &headers.kid {
        entries.push((Value::int(KID), Value::Bytes(kid.clone())));
    }
    cbor::encode(&canonical_map(entries))
}

/// `Sig_structure = ["Signature1", body_protected, external_aad, payload]`.
fn to_be_signed(protected: &[u8], external_aad: &[u8], payload: &[u8]) -> Vec<u8> {
    cbor::encode(&Value::Array(vec![
        Value::Text("Signature1".into()),
        Value::Bytes(protected.to_vec()),
        Value::Bytes(external_aad.to_vec()),
        Value::Bytes(payload.to_vec()),
    ]))
}

fn sign_inner(
    key: &SigningKey,
    payload: &[u8],
    headers: &Headers,
    external_aad: &[u8],
    attached: bool,
) -> Result<Vec<u8>> {
    let protected = protected_header(key.algorithm(), headers);
    let signature = key.sign(&to_be_signed(&protected, external_aad, payload))?;
    Ok(cbor::encode(&Value::Tag(
        TAG,
        Box::new(Value::Array(vec![
            Value::Bytes(protected),
            Value::Map(Vec::new()),
            if attached {
                Value::Bytes(payload.to_vec())
            } else {
                Value::Null
            },
            Value::Bytes(signature),
        ])),
    )))
}

/// Sign `payload` into a tagged `COSE_Sign1` with the payload attached. `external_aad` is
/// authenticated but not transmitted (use `&[]` if none); the verifier must pass the same.
pub fn sign(
    key: &SigningKey,
    payload: &[u8],
    headers: &Headers,
    external_aad: &[u8],
) -> Result<Vec<u8>> {
    sign_inner(key, payload, headers, external_aad, true)
}

/// Like [`sign`], but the payload is not included (`nil`); the verifier supplies it.
pub fn sign_detached(
    key: &SigningKey,
    payload: &[u8],
    headers: &Headers,
    external_aad: &[u8],
) -> Result<Vec<u8>> {
    sign_inner(key, payload, headers, external_aad, false)
}

/// Verify a `COSE_Sign1` with an attached payload.
pub fn verify(message: &[u8], key: &VerifyingKey, external_aad: &[u8]) -> Result<Verified> {
    verify_inner(&cbor::decode(message)?, key, external_aad, None)
}

/// Verify a `COSE_Sign1` whose payload is detached.
pub fn verify_detached(
    message: &[u8],
    payload: &[u8],
    key: &VerifyingKey,
    external_aad: &[u8],
) -> Result<Verified> {
    verify_inner(&cbor::decode(message)?, key, external_aad, Some(payload))
}

fn header_params(map: &Value) -> Result<(Option<ContentType>, Option<Vec<u8>>)> {
    let ct = match map.get(CONTENT_TYPE) {
        None => None,
        Some(Value::Uint(n)) if *n <= 0xffff => Some(ContentType::Format(*n)),
        Some(Value::Text(t)) => Some(ContentType::MediaType(t.clone())),
        Some(_) => return Err(Error::Malformed("content type header")),
    };
    let kid = match map.get(KID) {
        None => None,
        Some(Value::Bytes(k)) => Some(k.clone()),
        Some(_) => return Err(Error::Malformed("kid header")),
    };
    Ok((ct, kid))
}

/// Verify an already decoded message (tag 18 optional). Used by CWT too.
pub(crate) fn verify_inner(
    value: &Value,
    key: &VerifyingKey,
    external_aad: &[u8],
    detached: Option<&[u8]>,
) -> Result<Verified> {
    let value = match value {
        Value::Tag(TAG, inner) => inner,
        Value::Tag(..) => return Err(Error::Malformed("not a COSE_Sign1 (wrong tag)")),
        other => other,
    };
    let Value::Array(parts) = value else {
        return Err(Error::Malformed("COSE_Sign1 is not an array"));
    };
    let [protected, unprotected, payload, signature] = parts.as_slice() else {
        return Err(Error::Malformed("COSE_Sign1 must have four elements"));
    };
    let protected_bytes = protected
        .as_bytes()
        .ok_or(Error::Malformed("protected header is not a byte string"))?;
    let protected_map = if protected_bytes.is_empty() {
        Value::Map(Vec::new())
    } else {
        cbor::decode(protected_bytes)?
    };
    let (Value::Map(p), Value::Map(u)) = (&protected_map, unprotected) else {
        return Err(Error::Malformed("header is not a map"));
    };
    if p.iter().any(|(k, _)| u.iter().any(|(k2, _)| k == k2)) {
        return Err(Error::Malformed(
            "a label appears in both the protected and unprotected header",
        ));
    }
    if protected_map.get(CRIT).is_some() || unprotected.get(CRIT).is_some() {
        return Err(Error::UnsupportedCritical);
    }
    let alg = protected_map
        .get(ALG)
        .ok_or(Error::Malformed("alg must be in the protected header"))?
        .as_i64()
        .ok_or(Error::Malformed("alg must be an integer"))?;
    if Algorithm::from_id(alg)? != key.algorithm() {
        return Err(Error::AlgorithmMismatch);
    }
    let payload = match (payload, detached) {
        (Value::Bytes(p), None) => p.as_slice(),
        (Value::Null, Some(p)) => p,
        (Value::Null, None) => return Err(Error::Malformed("payload is detached")),
        (Value::Bytes(_), Some(_)) => return Err(Error::Malformed("payload is not detached")),
        _ => return Err(Error::Malformed("payload is not a byte string")),
    };
    let signature = signature
        .as_bytes()
        .ok_or(Error::Malformed("signature is not a byte string"))?;
    key.verify(
        &to_be_signed(protected_bytes, external_aad, payload),
        signature,
    )?;
    let (content_type, pkid) = header_params(&protected_map)?;
    let (u_ct, ukid) = header_params(unprotected)?;
    Ok(Verified {
        payload: payload.to_vec(),
        headers: Headers {
            kid: pkid.clone().or(ukid),
            content_type: content_type.or(u_ct),
        },
        kid_protected: pkid.is_some(),
    })
}

/// The key identifier of a message, read without verifying it, to select the key.
pub fn peek_kid(message: &[u8]) -> Result<Option<Vec<u8>>> {
    let value = cbor::decode(message)?;
    let inner = match &value {
        Value::Tag(61, inner) => inner.as_ref(),
        v => v,
    };
    let inner = match inner {
        Value::Tag(TAG, inner) => inner.as_ref(),
        v => v,
    };
    let Value::Array(parts) = inner else {
        return Err(Error::Malformed("COSE_Sign1 is not an array"));
    };
    let (Some(protected), Some(unprotected)) = (parts.first(), parts.get(1)) else {
        return Err(Error::Malformed("COSE_Sign1 must have four elements"));
    };
    let p = match protected.as_bytes() {
        Some([]) => Value::Map(Vec::new()),
        Some(b) => cbor::decode(b)?,
        None => return Err(Error::Malformed("protected header is not a byte string")),
    };
    let (_, pkid) = header_params(&p)?;
    let (_, ukid) = header_params(unprotected)?;
    Ok(pkid.or(ukid))
}
