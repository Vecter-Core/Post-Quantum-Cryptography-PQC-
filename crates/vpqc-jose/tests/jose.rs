//! JWS, JWK and JWT behaviour, including rejection of known JOSE attack patterns.

use serde_json::{Map, Value, json};
use vpqc_jose::jwt::{self, Validation};
use vpqc_jose::{Algorithm, Error, SigningKey, VerifyingKey, jws};

fn b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn obj(v: Value) -> Map<String, Value> {
    v.as_object().unwrap().clone()
}

/// Replace the header of a token (keeping payload and signature).
fn with_header(token: &str, header: &str) -> String {
    let rest = &token[token.find('.').unwrap()..];
    format!("{}{rest}", b64(header.as_bytes()))
}

#[test]
fn sign_verify_both_algorithms() {
    for alg in [Algorithm::MlDsa65, Algorithm::MlDsa87] {
        let key = SigningKey::generate(alg).unwrap();
        let token = jws::sign(&key, b"payload", &obj(json!({"kid": "k1"}))).unwrap();
        let v = jws::verify(&token, &key.verifying_key()).unwrap();
        assert_eq!(v.payload, b"payload");
        assert_eq!(v.header["alg"], alg.name());
        assert_eq!(v.header["kid"], "k1");
        let sig_len = token.rsplit('.').next().unwrap().len();
        assert_eq!(sig_len, b64(&vec![0; alg.signature_len()]).len());
    }
}

#[test]
fn jwk_round_trip_and_thumbprint() {
    let key = SigningKey::from_seed(Algorithm::MlDsa65, &[7; 32]);
    let private = key.to_jwk();
    let again = SigningKey::from_jwk(&private).unwrap();
    assert_eq!(again.verifying_key(), key.verifying_key());
    assert_eq!(again.to_jwk(), private);

    let public = key.verifying_key().to_jwk();
    assert!(!public.contains("priv"));
    assert_eq!(
        VerifyingKey::from_jwk(&public).unwrap(),
        key.verifying_key()
    );

    let tp = key.verifying_key().thumbprint();
    assert_eq!(tp.len(), 43);
    // Member order and extra members do not change the key (RFC 7638).
    let v: Value = serde_json::from_str(&public).unwrap();
    let reordered = format!(
        r#"{{"pub":{},"use":"sig","kid":"x","kty":"AKP","alg":"ML-DSA-65"}}"#,
        v["pub"]
    );
    assert_eq!(VerifyingKey::from_jwk(&reordered).unwrap().thumbprint(), tp);
}

#[test]
fn jwk_rejections() {
    let key = SigningKey::from_seed(Algorithm::MlDsa65, &[1; 32]);
    let other = SigningKey::from_seed(Algorithm::MlDsa65, &[2; 32]);
    let v: Value = serde_json::from_str(&key.to_jwk()).unwrap();
    let (pubk, privk) = (v["pub"].as_str().unwrap(), v["priv"].as_str().unwrap());
    let other_pub = serde_json::from_str::<Value>(&other.to_jwk()).unwrap()["pub"].clone();

    let bad_public = [
        (
            format!(r#"{{"kty":"OKP","alg":"ML-DSA-65","pub":"{pubk}"}}"#),
            "kty",
        ),
        (format!(r#"{{"kty":"AKP","pub":"{pubk}"}}"#), "missing alg"),
        (
            format!(r#"{{"kty":"AKP","alg":"ML-DSA-87","pub":"{pubk}"}}"#),
            "length vs alg",
        ),
        (
            format!(r#"{{"kty":"AKP","alg":"none","pub":"{pubk}"}}"#),
            "alg none",
        ),
        (
            format!(r#"{{"kty":"AKP","alg":"ML-DSA-65","pub":"{pubk}","use":"enc"}}"#),
            "use",
        ),
        (
            format!(r#"{{"kty":"AKP","alg":"ML-DSA-65","pub":"{pubk}","key_ops":["encrypt"]}}"#),
            "key_ops",
        ),
        (
            format!(r#"{{"kty":"AKP","alg":"ML-DSA-65","pub":"{pubk}","pub":"{pubk}"}}"#),
            "duplicate",
        ),
        (
            format!(r#"{{"kty":"AKP","alg":"ML-DSA-65","pub":"{pubk}="}}"#),
            "padding",
        ),
        (
            format!(r#"{{"kty":"AKP","alg":"ML-DSA-65","pub":"{pubk}","priv":"{privk}"}}"#),
            "priv in public",
        ),
    ];
    for (jwk, why) in bad_public {
        assert!(VerifyingKey::from_jwk(&jwk).is_err(), "{why}");
    }

    let mismatched =
        format!(r#"{{"kty":"AKP","alg":"ML-DSA-65","pub":{other_pub},"priv":"{privk}"}}"#);
    assert_eq!(
        SigningKey::from_jwk(&mismatched).unwrap_err(),
        Error::InvalidKey("pub does not match priv")
    );
    let short = format!(r#"{{"kty":"AKP","alg":"ML-DSA-65","pub":"{pubk}","priv":"AAAA"}}"#);
    assert!(SigningKey::from_jwk(&short).is_err());
    let no_priv = key.verifying_key().to_jwk();
    assert!(SigningKey::from_jwk(&no_priv).is_err());
}

#[test]
fn verify_rejections() {
    let key = SigningKey::generate(Algorithm::MlDsa65).unwrap();
    let public = key.verifying_key();
    let token = jws::sign(&key, b"payload", &Map::new()).unwrap();
    let [h, p, s]: [&str; 3] = token.split('.').collect::<Vec<_>>().try_into().unwrap();

    // Algorithm confusion.
    let none = with_header(&token, r#"{"alg":"none"}"#);
    assert!(matches!(
        jws::verify(&none, &public),
        Err(Error::UnsupportedAlgorithm(_))
    ));
    let key87 = SigningKey::generate(Algorithm::MlDsa87).unwrap();
    let t87 = jws::sign(&key87, b"payload", &Map::new()).unwrap();
    assert_eq!(
        jws::verify(&t87, &public).unwrap_err(),
        Error::AlgorithmMismatch
    );
    let lower = with_header(&token, r#"{"alg":"ml-dsa-65"}"#);
    assert!(jws::verify(&lower, &public).is_err());
    let no_alg = with_header(&token, r#"{"kid":"x"}"#);
    assert!(jws::verify(&no_alg, &public).is_err());

    // Extensions.
    let crit = with_header(&token, r#"{"alg":"ML-DSA-65","crit":["exp"],"exp":1}"#);
    assert_eq!(
        jws::verify(&crit, &public).unwrap_err(),
        Error::UnsupportedCritical
    );
    let b64false = with_header(&token, r#"{"alg":"ML-DSA-65","b64":false}"#);
    assert_eq!(
        jws::verify(&b64false, &public).unwrap_err(),
        Error::UnsupportedCritical
    );
    let dup = with_header(&token, r#"{"alg":"ML-DSA-65","alg":"ML-DSA-65"}"#);
    assert!(matches!(
        jws::verify(&dup, &public),
        Err(Error::Malformed(_))
    ));

    // Any change to header, payload or signature.
    let same_meaning = with_header(&token, r#"{ "alg":"ML-DSA-65"}"#);
    assert_eq!(
        jws::verify(&same_meaning, &public).unwrap_err(),
        Error::VerificationFailed
    );
    let other_payload = format!("{h}.{}.{s}", b64(b"PAYLOAD"));
    assert_eq!(
        jws::verify(&other_payload, &public).unwrap_err(),
        Error::VerificationFailed
    );
    let mut sig = s.to_owned().into_bytes();
    sig[10] = if sig[10] == b'A' { b'B' } else { b'A' };
    let flipped = format!("{h}.{p}.{}", String::from_utf8(sig).unwrap());
    assert_eq!(
        jws::verify(&flipped, &public).unwrap_err(),
        Error::VerificationFailed
    );
    let other_key = SigningKey::generate(Algorithm::MlDsa65)
        .unwrap()
        .verifying_key();
    assert_eq!(
        jws::verify(&token, &other_key).unwrap_err(),
        Error::VerificationFailed
    );

    // Encoding.
    for bad in [
        format!("{token}."),
        format!("{h}.{p}"),
        format!("{h}.{p}.{s}="),
        format!("{h}.{p}.{s}\n"),
        format!("{h}.{p}.{}", &s[..s.len() - 1]),
        format!("{h}=.{p}.{s}"),
        "a".repeat(jws::MAX_TOKEN_LEN + 1),
    ] {
        assert!(jws::verify(&bad, &public).is_err(), "{bad:.40}");
    }
    // Non-canonical base64url: the 19-byte header `{"alg":"ML-DSA-65"}` ends in a character
    // with 4 unused bits; setting them must be rejected, not silently ignored.
    assert_eq!(h.len() % 4, 2);
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let last = alphabet
        .iter()
        .position(|&c| c == h.as_bytes()[h.len() - 1])
        .unwrap();
    let noncanon = format!(
        "{}{}.{p}.{s}",
        &h[..h.len() - 1],
        alphabet[last | 1] as char
    );
    assert_ne!(last | 1, last);
    assert!(matches!(
        jws::verify(&noncanon, &public),
        Err(Error::Malformed(_))
    ));

    // Header parameters the library owns.
    for reserved in ["alg", "crit", "b64"] {
        let mut extra = Map::new();
        extra.insert(reserved.into(), "x".into());
        assert!(jws::sign(&key, b"x", &extra).is_err());
    }
}

#[test]
fn jwt_claims() {
    let key = SigningKey::generate(Algorithm::MlDsa65).unwrap();
    let public = key.verifying_key();
    let at = |now: u64| Validation {
        now: Some(now),
        ..Validation::default()
    };
    let token = |claims: Value| {
        let mut header = Map::new();
        header.insert("typ".into(), "JWT".into());
        jwt::encode_with_header(&key, &obj(claims), &header).unwrap()
    };

    let t = token(json!({"sub": "a", "exp": 1000, "nbf": 500}));
    assert!(jwt::decode(&t, &public, &at(700)).is_ok());
    assert!(jwt::decode(&t, &public, &at(1059)).is_ok()); // within 60 s leeway
    assert_eq!(
        jwt::decode(&t, &public, &at(1060)).unwrap_err(),
        Error::InvalidClaim("exp")
    );
    assert_eq!(
        jwt::decode(&t, &public, &at(439)).unwrap_err(),
        Error::InvalidClaim("nbf")
    );
    let strict = Validation {
        leeway: 0,
        ..at(1000)
    };
    assert_eq!(
        jwt::decode(&t, &public, &strict).unwrap_err(),
        Error::InvalidClaim("exp")
    );

    let no_exp = token(json!({"sub": "a"}));
    assert_eq!(
        jwt::decode(&no_exp, &public, &at(1)).unwrap_err(),
        Error::InvalidClaim("exp")
    );
    let optional = Validation {
        require_exp: false,
        ..at(1)
    };
    assert!(jwt::decode(&no_exp, &public, &optional).is_ok());
    let string_exp = token(json!({"exp": "1000"}));
    assert_eq!(
        jwt::decode(&string_exp, &public, &at(1)).unwrap_err(),
        Error::InvalidClaim("exp")
    );

    // Issuer and audience.
    let t = token(json!({"exp": 1000, "iss": "https://idp", "aud": ["api", "web"]}));
    let with = |iss: Option<&str>, aud: Option<&str>| Validation {
        issuer: iss.map(Into::into),
        audience: aud.map(Into::into),
        ..at(1)
    };
    assert!(jwt::decode(&t, &public, &with(Some("https://idp"), Some("api"))).is_ok());
    assert_eq!(
        jwt::decode(&t, &public, &with(Some("https://evil"), Some("api"))).unwrap_err(),
        Error::InvalidClaim("iss")
    );
    assert_eq!(
        jwt::decode(&t, &public, &with(None, Some("other"))).unwrap_err(),
        Error::InvalidClaim("aud")
    );
    assert_eq!(
        jwt::decode(&t, &public, &with(None, None)).unwrap_err(),
        Error::InvalidClaim("aud")
    );
    let no_aud = token(json!({"exp": 1000}));
    assert_eq!(
        jwt::decode(&no_aud, &public, &with(None, Some("api"))).unwrap_err(),
        Error::InvalidClaim("aud")
    );

    // Explicit typing.
    let mut at_header = Map::new();
    at_header.insert("typ".into(), "at+jwt".into());
    let access = jwt::encode_with_header(&key, &obj(json!({"exp": 1000})), &at_header).unwrap();
    let want_at = Validation {
        typ: Some("AT+JWT".into()),
        ..at(1)
    };
    assert!(jwt::decode(&access, &public, &want_at).is_ok());
    assert_eq!(
        jwt::decode(&access, &public, &at(1)).unwrap_err(),
        Error::InvalidClaim("typ")
    );
    let untyped = jwt::encode_with_header(&key, &obj(json!({"exp": 1000})), &Map::new()).unwrap();
    assert!(jwt::decode(&untyped, &public, &at(1)).is_ok());
    assert_eq!(
        jwt::decode(&untyped, &public, &want_at).unwrap_err(),
        Error::InvalidClaim("typ")
    );

    // Claims must be a JSON object with unique members.
    let raw = |payload: &[u8]| jws::sign(&key, payload, &Map::new()).unwrap();
    assert!(jwt::decode(&raw(br#"{"exp":1000,"exp":9999999999}"#), &public, &at(1)).is_err());
    assert!(jwt::decode(&raw(b"[1]"), &public, &at(1)).is_err());
}

#[test]
fn jwt_encode_sets_times_and_kid() {
    let key = SigningKey::generate(Algorithm::MlDsa87).unwrap();
    let mut claims = Map::new();
    claims.insert("exp".into(), 1.into()); // replaced
    let token = jwt::encode(&key, claims, 300).unwrap();
    let header = jws::decode_header(&token).unwrap();
    assert_eq!(header["kid"], key.verifying_key().thumbprint());
    assert_eq!(header["typ"], "JWT");
    let claims = jwt::decode(&token, &key.verifying_key(), &Validation::default()).unwrap();
    let (iat, exp) = (
        claims["iat"].as_u64().unwrap(),
        claims["exp"].as_u64().unwrap(),
    );
    assert_eq!(exp - iat, 300);
}
