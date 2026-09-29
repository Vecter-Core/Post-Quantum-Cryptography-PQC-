//! COSE/CWT: untrusted CBOR, COSE_Keys, COSE_Sign1 messages and CWTs never panic; the strict
//! decoder accepts only one encoding per value (float-free input re-encodes byte for byte);
//! keys round-trip; nothing verifies under the fixed key except what it really signed.
#![no_main]
use libfuzzer_sys::fuzz_target;
use vpqc_cose::cbor::{self, Value};
use vpqc_cose::{SigningKey, VerifyingKey, cwt, sign1};
use vpqc_fuzz::{COSE_PAYLOAD, cose_key};

fn has_float(v: &Value) -> bool {
    match v {
        Value::Float(_) => true,
        Value::Array(items) => items.iter().any(has_float),
        Value::Map(entries) => entries.iter().any(|(k, v)| has_float(k) || has_float(v)),
        Value::Tag(_, inner) => has_float(inner),
        _ => false,
    }
}

fuzz_target!(|data: &[u8]| {
    if let Ok(v) = cbor::decode(data) {
        let again = cbor::encode(&v);
        if !has_float(&v) {
            assert_eq!(again, data, "a value decoded from a non-canonical encoding");
        }
        assert_eq!(cbor::encode(&cbor::decode(&again).unwrap()), again);
    }
    if let Ok(k) = VerifyingKey::from_cose_key(data) {
        assert_eq!(VerifyingKey::from_cose_key(&k.to_cose_key()).unwrap(), k);
    }
    if let Ok(k) = SigningKey::from_cose_key(data) {
        let again = SigningKey::from_cose_key(&k.to_cose_key()).unwrap();
        assert_eq!(again.verifying_key(), k.verifying_key());
    }
    let _ = sign1::peek_kid(data);
    let key = cose_key();
    if let Ok(v) = sign1::verify(data, key, b"") {
        // Either the signed payload, or the claims of the signed CWT (subject COSE_PAYLOAD).
        let cwt_claims = cbor::decode(&v.payload)
            .is_ok_and(|c| c.get(2).and_then(Value::as_text) == Some(COSE_PAYLOAD));
        assert!(v.payload == COSE_PAYLOAD.as_bytes() || cwt_claims, "forged COSE_Sign1 accepted");
    }
    let _ = sign1::verify_detached(data, COSE_PAYLOAD.as_bytes(), key, b"");
    let lax = cwt::Validation { require_exp: false, now: Some(0), ..cwt::Validation::default() };
    if let Ok(claims) = cwt::decode(data, key, &lax) {
        assert_eq!(claims.sub.as_deref(), Some(COSE_PAYLOAD), "forged CWT accepted");
    }
});
