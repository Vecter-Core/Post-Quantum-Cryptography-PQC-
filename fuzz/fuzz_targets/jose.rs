//! JOSE: untrusted tokens and JWKs never panic and are accepted only with a valid signature;
//! sign/verify round-trips for any payload; any single-bit change to a token is rejected.
#![no_main]
use libfuzzer_sys::fuzz_target;
use serde_json::Map;
use vpqc_fuzz::{Input, jose_keys};
use vpqc_jose::jwt::{self, Validation};
use vpqc_jose::{SigningKey, VerifyingKey, jws};

fuzz_target!(|data: &[u8]| {
    let mut input = Input(data);
    let mode = input.byte();
    let key = &jose_keys()[(input.byte() & 1) as usize];
    let public = key.verifying_key();
    match mode % 3 {
        0 => {
            let token = String::from_utf8_lossy(input.rest());
            let _ = jws::decode_header(&token);
            if let Ok(v) = jws::verify(&token, &public) {
                // Accepted only if it really is a valid token for this key.
                assert_eq!(v.header["alg"], key.algorithm().name());
            }
            let now = Validation { now: Some(1_000_000), ..Validation::default() };
            let _ = jwt::decode(&token, &public, &now);
        }
        1 => {
            let jwk = String::from_utf8_lossy(input.rest());
            if let Ok(k) = VerifyingKey::from_jwk(&jwk) {
                assert_eq!(VerifyingKey::from_jwk(&k.to_jwk()).unwrap(), k);
            }
            if let Ok(k) = SigningKey::from_jwk(&jwk) {
                assert_eq!(SigningKey::from_jwk(&k.to_jwk()).unwrap().verifying_key(), k.verifying_key());
            }
        }
        _ => {
            let (pos, bit) = (input.byte() as usize, input.byte() & 7);
            let payload = input.rest();
            let token = jws::sign(key, payload, &Map::new()).unwrap();
            assert_eq!(jws::verify(&token, &public).unwrap().payload, payload);
            let mut bytes = token.clone().into_bytes();
            let i = (pos * 131) % bytes.len();
            bytes[i] ^= 1 << bit;
            if let Ok(mutated) = String::from_utf8(bytes) {
                assert!(jws::verify(&mutated, &public).is_err(), "mutated token accepted");
            }
        }
    }
});
