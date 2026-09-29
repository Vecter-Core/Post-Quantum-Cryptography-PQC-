//! COSE_Key, COSE_Sign1 and CWT: round trips, rejections, and cross-checks against `coset`,
//! an independent COSE implementation.

use coset::{
    CborSerializable, CoseKey, CoseKeyBuilder, CoseSign1, CoseSign1Builder, HeaderBuilder,
    TaggedCborSerializable, cwt::ClaimsSet, iana, iana::EnumI64,
};
use vpqc_backend_libcrux::mldsa::{self, Level};
use vpqc_cose::cbor::{self, Value};
use vpqc_cose::sign1::{self, ContentType, Headers};
use vpqc_cose::{Algorithm, Error, SigningKey, VerifyingKey, cwt};

fn key(alg: Algorithm, n: u8) -> SigningKey {
    SigningKey::from_seed(alg, &[n; 32])
}

fn level(alg: Algorithm) -> Level {
    match alg {
        Algorithm::MlDsa65 => Level::L65,
        _ => Level::L87,
    }
}

fn coset_alg(alg: Algorithm) -> iana::Algorithm {
    match alg {
        Algorithm::MlDsa65 => iana::Algorithm::ML_DSA_65,
        _ => iana::Algorithm::ML_DSA_87,
    }
}

#[test]
fn cose_keys_round_trip_and_match_coset() {
    for alg in [Algorithm::MlDsa65, Algorithm::MlDsa87] {
        let k = key(alg, 1);
        let public = k.verifying_key();
        let encoded = public.to_cose_key();
        assert_eq!(VerifyingKey::from_cose_key(&encoded).unwrap(), public);
        // Byte-identical to coset's encoding of the same key.
        let variant = match alg {
            Algorithm::MlDsa65 => coset::MlDsaVariant::MlDsa65,
            _ => coset::MlDsaVariant::MlDsa87,
        };
        let theirs = CoseKeyBuilder::new_mldsa_pub_key(variant, public.as_bytes().to_vec())
            .build()
            .to_vec()
            .unwrap();
        assert_eq!(encoded, theirs);

        let private = k.to_cose_key();
        let back = SigningKey::from_cose_key(&private).unwrap();
        assert_eq!(back.verifying_key(), public);
        // coset reads the private key too: kty AKP, alg, pub (-1) and the 32-byte seed (-2).
        let parsed = CoseKey::from_slice(&private).unwrap();
        assert_eq!(parsed.kty, coset::KeyType::Assigned(iana::KeyType::AKP));
        assert_eq!(parsed.alg, Some(coset::Algorithm::Assigned(coset_alg(alg))));
        let seed = parsed
            .params
            .iter()
            .find(|(l, _)| *l == coset::Label::Int(-2))
            .unwrap();
        assert_eq!(seed.1.as_bytes().unwrap(), &vec![1u8; 32]);
        // Tag 101 is accepted.
        let tagged = cbor::encode(&Value::Tag(101, Box::new(cbor::decode(&encoded).unwrap())));
        assert_eq!(VerifyingKey::from_cose_key(&tagged).unwrap(), public);
    }
}

#[test]
fn malformed_keys_are_rejected() {
    let k = key(Algorithm::MlDsa65, 2);
    let private = k.to_cose_key();
    assert!(matches!(
        VerifyingKey::from_cose_key(&private),
        Err(Error::InvalidKey(_))
    ));
    let public = k.verifying_key();
    let pub_map = |entries: Vec<(i64, Value)>| {
        cbor::encode(&Value::Map(
            entries
                .into_iter()
                .map(|(l, v)| (Value::int(l), v))
                .collect(),
        ))
    };
    let pk = || Value::Bytes(public.as_bytes().to_vec());
    for (bad, why) in [
        (
            pub_map(vec![(1, Value::int(1)), (3, Value::int(-49)), (-1, pk())]),
            "OKP",
        ),
        (pub_map(vec![(3, Value::int(-49)), (-1, pk())]), "no kty"),
        (pub_map(vec![(1, Value::int(7)), (-1, pk())]), "no alg"),
        (
            pub_map(vec![(1, Value::int(7)), (3, Value::int(-48)), (-1, pk())]),
            "ML-DSA-44",
        ),
        (
            pub_map(vec![(1, Value::int(7)), (3, Value::int(-50)), (-1, pk())]),
            "87 with 65 key",
        ),
        (
            pub_map(vec![(1, Value::int(7)), (3, Value::int(-49))]),
            "no pub",
        ),
        (
            pub_map(vec![
                (1, Value::int(7)),
                (3, Value::int(-49)),
                (-1, Value::Text("x".into())),
            ]),
            "text pub",
        ),
        (
            pub_map(vec![
                (1, Value::int(7)),
                (3, Value::int(-49)),
                (4, Value::Array(vec![Value::int(3)])),
                (-1, pk()),
            ]),
            "key_ops encrypt",
        ),
    ] {
        assert!(VerifyingKey::from_cose_key(&bad).is_err(), "{why}");
    }
    // A private key whose pub does not match priv.
    let other = key(Algorithm::MlDsa65, 3);
    let mismatched = pub_map(vec![
        (1, Value::int(7)),
        (3, Value::int(-49)),
        (-1, Value::Bytes(other.verifying_key().as_bytes().to_vec())),
        (-2, Value::Bytes(vec![2; 32])),
    ]);
    assert_eq!(
        SigningKey::from_cose_key(&mismatched).unwrap_err(),
        Error::InvalidKey("pub does not match priv")
    );
    // Every truncation fails.
    for n in 0..private.len() {
        assert!(SigningKey::from_cose_key(&private[..n]).is_err(), "{n}");
    }
}

#[test]
fn sign1_round_trips() {
    let k = key(Algorithm::MlDsa65, 4);
    let pk = k.verifying_key();
    let headers = Headers {
        kid: Some(b"device-17".to_vec()),
        content_type: Some(ContentType::Format(60)),
    };
    let msg = sign1::sign(&k, b"reading=21.5C", &headers, b"").unwrap();
    let v = sign1::verify(&msg, &pk, b"").unwrap();
    assert_eq!(v.payload, b"reading=21.5C");
    assert_eq!(v.headers, headers);
    assert!(v.kid_protected);
    assert_eq!(sign1::peek_kid(&msg).unwrap(), Some(b"device-17".to_vec()));

    // External AAD binds context that is not transmitted.
    let msg = sign1::sign(&k, b"x", &Headers::default(), b"channel-7").unwrap();
    sign1::verify(&msg, &pk, b"channel-7").unwrap();
    assert_eq!(
        sign1::verify(&msg, &pk, b"channel-8").unwrap_err(),
        Error::VerificationFailed
    );

    // Detached payload.
    let det = sign1::sign_detached(&k, b"firmware image", &Headers::default(), b"").unwrap();
    assert!(det.len() < msg.len() + 16);
    sign1::verify_detached(&det, b"firmware image", &pk, b"").unwrap();
    assert!(sign1::verify_detached(&det, b"firmware imagE", &pk, b"").is_err());
    assert!(matches!(
        sign1::verify(&det, &pk, b""),
        Err(Error::Malformed(_))
    ));
    assert!(matches!(
        sign1::verify_detached(&msg, b"x", &pk, b""),
        Err(Error::Malformed(_))
    ));
}

#[test]
fn coset_verifies_vpqc_messages() {
    for alg in [Algorithm::MlDsa65, Algorithm::MlDsa87] {
        let k = key(alg, 5);
        let pk = k.verifying_key();
        let headers = Headers {
            kid: Some(vec![1, 2, 3]),
            content_type: Some(ContentType::MediaType("application/json".into())),
        };
        let msg = sign1::sign(&k, b"{\"t\":1}", &headers, b"aad").unwrap();
        let parsed = CoseSign1::from_tagged_slice(&msg).unwrap();
        assert_eq!(
            parsed.protected.header.alg,
            Some(coset::Algorithm::Assigned(coset_alg(alg)))
        );
        assert_eq!(parsed.protected.header.key_id, vec![1, 2, 3]);
        assert_eq!(parsed.payload.as_deref(), Some(&b"{\"t\":1}"[..]));
        parsed
            .verify_signature(b"aad", |sig, tbs| {
                mldsa::verify(level(alg), pk.as_bytes(), tbs, b"", sig)
            })
            .unwrap();
        assert!(
            parsed
                .verify_signature(b"other", |sig, tbs| {
                    mldsa::verify(level(alg), pk.as_bytes(), tbs, b"", sig)
                })
                .is_err()
        );
    }
}

/// A message built and signed by coset (with the key of seed 6) from the given headers.
fn coset_signed(
    k: &SigningKey,
    protected: coset::Header,
    unprotected: coset::Header,
    payload: &[u8],
) -> Vec<u8> {
    let seed = [6u8; 32];
    let (_, expanded) = mldsa::keygen(level(k.algorithm()), &seed);
    CoseSign1Builder::new()
        .protected(protected)
        .unprotected(unprotected)
        .payload(payload.to_vec())
        .create_signature(b"", |tbs| {
            mldsa::sign(level(k.algorithm()), &expanded, tbs, b"", &[9; 32]).unwrap()
        })
        .build()
        .to_tagged_vec()
        .unwrap()
}

#[test]
fn vpqc_verifies_coset_messages_and_enforces_header_rules() {
    let k = key(Algorithm::MlDsa65, 6);
    let pk = k.verifying_key();
    let alg = iana::Algorithm::ML_DSA_65;
    let good = coset_signed(
        &k,
        HeaderBuilder::new()
            .algorithm(alg)
            .key_id(b"k1".to_vec())
            .build(),
        HeaderBuilder::new().build(),
        b"hello",
    );
    let v = sign1::verify(&good, &pk, b"").unwrap();
    assert_eq!(v.payload, b"hello");
    assert_eq!(v.headers.kid.as_deref(), Some(&b"k1"[..]));

    // kid only in the unprotected header: accepted, but reported as unprotected.
    let unprot_kid = coset_signed(
        &k,
        HeaderBuilder::new().algorithm(alg).build(),
        HeaderBuilder::new().key_id(b"k2".to_vec()).build(),
        b"hello",
    );
    let v = sign1::verify(&unprot_kid, &pk, b"").unwrap();
    assert!(!v.kid_protected);
    assert_eq!(v.headers.kid.as_deref(), Some(&b"k2"[..]));

    // alg only in the unprotected header.
    let alg_unprotected = coset_signed(
        &k,
        HeaderBuilder::new().build(),
        HeaderBuilder::new().algorithm(alg).build(),
        b"hello",
    );
    assert!(matches!(
        sign1::verify(&alg_unprotected, &pk, b""),
        Err(Error::Malformed(_))
    ));
    // Critical parameters.
    let crit = coset_signed(
        &k,
        HeaderBuilder::new()
            .algorithm(alg)
            .add_critical(iana::HeaderParameter::Kid)
            .key_id(b"k".to_vec())
            .build(),
        HeaderBuilder::new().build(),
        b"hello",
    );
    assert_eq!(
        sign1::verify(&crit, &pk, b"").unwrap_err(),
        Error::UnsupportedCritical
    );
    // The same label in both buckets.
    let both = coset_signed(
        &k,
        HeaderBuilder::new()
            .algorithm(alg)
            .key_id(b"a".to_vec())
            .build(),
        HeaderBuilder::new().key_id(b"b".to_vec()).build(),
        b"hello",
    );
    assert!(matches!(
        sign1::verify(&both, &pk, b""),
        Err(Error::Malformed(_))
    ));
    // Another algorithm (ES256) and a different ML-DSA level.
    let es256 = coset_signed(
        &k,
        HeaderBuilder::new()
            .algorithm(iana::Algorithm::ES256)
            .build(),
        HeaderBuilder::new().build(),
        b"hello",
    );
    assert_eq!(
        sign1::verify(&es256, &pk, b"").unwrap_err(),
        Error::UnsupportedAlgorithm(iana::Algorithm::ES256.to_i64())
    );
    let k87 = key(Algorithm::MlDsa87, 6);
    let msg87 = sign1::sign(&k87, b"x", &Headers::default(), b"").unwrap();
    assert_eq!(
        sign1::verify(&msg87, &pk, b"").unwrap_err(),
        Error::AlgorithmMismatch
    );
}

#[test]
fn tampering_and_malformed_messages_are_rejected() {
    let k = key(Algorithm::MlDsa65, 7);
    let pk = k.verifying_key();
    let msg = sign1::sign(&k, b"payload", &Headers::default(), b"").unwrap();
    // Every header byte, then a stride through the signature (each flip costs a verification).
    for i in (0..msg.len()).filter(|&i| i < 64 || i % 17 == 0) {
        let mut bad = msg.clone();
        bad[i] ^= 0x01;
        assert!(sign1::verify(&bad, &pk, b"").is_err(), "byte {i}");
    }
    for n in (0..msg.len()).filter(|&n| n < 64 || n % 13 == 0) {
        assert!(sign1::verify(&msg[..n], &pk, b"").is_err(), "prefix {n}");
    }
    let mut trailing = msg.clone();
    trailing.push(0);
    assert!(sign1::verify(&trailing, &pk, b"").is_err());
    // Untagged is accepted, another tag is not.
    let Value::Tag(18, inner) = cbor::decode(&msg).unwrap() else {
        panic!()
    };
    sign1::verify(&cbor::encode(&inner), &pk, b"").unwrap();
    let wrong_tag = cbor::encode(&Value::Tag(98, inner.clone()));
    assert!(sign1::verify(&wrong_tag, &pk, b"").is_err());
    // Another key of the same algorithm.
    let other = key(Algorithm::MlDsa65, 8).verifying_key();
    assert_eq!(
        sign1::verify(&msg, &other, b"").unwrap_err(),
        Error::VerificationFailed
    );
}

#[test]
fn cwt_round_trip_and_claim_checks() {
    let k = key(Algorithm::MlDsa65, 9);
    let pk = k.verifying_key();
    let claims = cwt::Claims {
        iss: Some("coap://as.example.com".into()),
        sub: Some("sensor-17".into()),
        aud: Some("coap://light.example.com".into()),
        cti: Some(vec![0x0b, 0x71]),
        other: vec![(Value::int(-65537), Value::Text("private".into()))],
        ..cwt::Claims::default()
    };
    let token = cwt::encode(&k, claims.clone(), 600).unwrap();
    let aud = |a: &str| cwt::Validation {
        audience: Some(a.into()),
        ..cwt::Validation::default()
    };
    let got = cwt::decode(&token, &pk, &aud("coap://light.example.com")).unwrap();
    assert_eq!(got.sub, claims.sub);
    assert_eq!(got.cti, claims.cti);
    assert_eq!(got.other, claims.other);
    assert_eq!(got.exp.unwrap() - got.iat.unwrap(), 600);

    // coset parses the claims set.
    let parsed = CoseSign1::from_tagged_slice(&token).unwrap();
    let set = ClaimsSet::from_slice(parsed.payload.as_deref().unwrap()).unwrap();
    assert_eq!(set.subject.as_deref(), Some("sensor-17"));
    assert_eq!(set.cwt_id, Some(vec![0x0b, 0x71]));

    // Audience rule: a token with aud needs the verifier's audience.
    assert_eq!(
        cwt::decode(&token, &pk, &cwt::Validation::default()).unwrap_err(),
        Error::InvalidClaim("aud")
    );
    assert_eq!(
        cwt::decode(&token, &pk, &aud("coap://other")).unwrap_err(),
        Error::InvalidClaim("aud")
    );
    // Issuer.
    let mut v = aud("coap://light.example.com");
    v.issuer = Some("coap://evil".into());
    assert_eq!(
        cwt::decode(&token, &pk, &v).unwrap_err(),
        Error::InvalidClaim("iss")
    );
    // Time: expired (beyond leeway), not yet valid.
    let mut v = aud("coap://light.example.com");
    v.now = Some(got.exp.unwrap() + 61);
    assert_eq!(
        cwt::decode(&token, &pk, &v).unwrap_err(),
        Error::InvalidClaim("exp")
    );
    v.now = Some(got.exp.unwrap() + 59);
    cwt::decode(&token, &pk, &v).unwrap();

    let nbf = cwt::Claims {
        nbf: Some(2_000_000_000),
        exp: Some(2_100_000_000),
        ..cwt::Claims::default()
    };
    let t = cwt::encode_with(&k, &nbf, &Headers::default(), b"").unwrap();
    let at = |now| cwt::Validation {
        now: Some(now),
        ..cwt::Validation::default()
    };
    assert_eq!(
        cwt::decode(&t, &pk, &at(1_999_999_000)).unwrap_err(),
        Error::InvalidClaim("nbf")
    );
    cwt::decode(&t, &pk, &at(1_999_999_950)).unwrap();

    // exp required by default.
    let no_exp = cwt::encode_with(&k, &cwt::Claims::default(), &Headers::default(), b"").unwrap();
    assert_eq!(
        cwt::decode(&no_exp, &pk, &cwt::Validation::default()).unwrap_err(),
        Error::InvalidClaim("exp")
    );
    let lax = cwt::Validation {
        require_exp: false,
        ..cwt::Validation::default()
    };
    cwt::decode(&no_exp, &pk, &lax).unwrap();

    // The optional CWT tag 61 is accepted.
    let tagged = cbor::encode(&Value::Tag(61, Box::new(cbor::decode(&token).unwrap())));
    cwt::decode(&tagged, &pk, &aud("coap://light.example.com")).unwrap();

    // Registered claims cannot be smuggled through `other`.
    let smuggle = cwt::Claims {
        other: vec![(Value::int(4), Value::int(0))],
        ..cwt::Claims::default()
    };
    assert!(cwt::encode_with(&k, &smuggle, &Headers::default(), b"").is_err());
}

#[test]
fn cwt_from_coset_with_audience_array_and_float_times() {
    let k = key(Algorithm::MlDsa65, 10);
    let pk = k.verifying_key();
    let seed = [10u8; 32];
    let (_, expanded) = mldsa::keygen(Level::L65, &seed);
    let now = 1_900_000_000i64;
    // coset only builds a text `aud`; the array form (used by ACE) is written directly.
    let claims = cbor::encode(&Value::Map(vec![
        (Value::int(1), Value::Text("as".into())),
        (
            Value::int(3),
            Value::Array(vec![Value::Text("a".into()), Value::Text("b".into())]),
        ),
        (Value::int(4), Value::Float((now + 100) as f64 + 0.5)),
    ]));
    // And coset's own claims set with a fractional expiry parses too.
    let from_coset = coset::cwt::ClaimsSetBuilder::new()
        .issuer("as".into())
        .audience("a".into())
        .expiration_time(coset::cwt::Timestamp::FractionalSeconds(
            (now + 100) as f64 + 0.5,
        ))
        .build()
        .to_vec()
        .unwrap();
    assert_eq!(
        cbor::decode(&from_coset).unwrap().get(4),
        Some(&Value::Float((now + 100) as f64 + 0.5))
    );
    let token = CoseSign1Builder::new()
        .protected(
            HeaderBuilder::new()
                .algorithm(iana::Algorithm::ML_DSA_65)
                .build(),
        )
        .payload(claims)
        .create_signature(b"", |tbs| {
            mldsa::sign(Level::L65, &expanded, tbs, b"", &[1; 32]).unwrap()
        })
        .build()
        .to_tagged_vec()
        .unwrap();
    let v = |aud: &str| cwt::Validation {
        audience: Some(aud.into()),
        now: Some(now),
        ..cwt::Validation::default()
    };
    let got = cwt::decode(&token, &pk, &v("b")).unwrap();
    assert_eq!(got.exp, Some(now + 100));
    assert_eq!(got.iss.as_deref(), Some("as"));
    assert_eq!(
        cwt::decode(&token, &pk, &v("c")).unwrap_err(),
        Error::InvalidClaim("aud")
    );
}
