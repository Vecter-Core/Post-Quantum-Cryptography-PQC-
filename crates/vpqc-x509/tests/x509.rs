//! Keys, certificate creation and chain verification, including the rejections.

use vpqc_x509::{
    Algorithm, Certificate, CertificateParams, Error, PrivateKey, PublicKey, Purpose,
    VerifyOptions, verify_chain,
};

const DAY: i64 = 86_400;

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

struct Pki {
    root_key: PrivateKey,
    root: Certificate,
    int_key: PrivateKey,
    int: Certificate,
    leaf_key: PrivateKey,
    leaf: Certificate,
}

fn pki(alg: Algorithm) -> Pki {
    let root_key = PrivateKey::generate(Algorithm::MlDsa87).unwrap();
    let root = CertificateParams::ca("Root", 3650)
        .path_len(1)
        .self_signed(&root_key)
        .unwrap();
    let int_key = PrivateKey::generate(alg).unwrap();
    let int = CertificateParams::ca("Intermediate", 365)
        .issue(int_key.public_key(), &root, &root_key)
        .unwrap();
    let leaf_key = PrivateKey::generate(alg).unwrap();
    let leaf = CertificateParams::end_entity("svc", 30)
        .dns_names(&["svc.example.com", "*.svc.example.com"])
        .purpose(Purpose::ServerAuth)
        .issue(leaf_key.public_key(), &int, &int_key)
        .unwrap();
    Pki {
        root_key,
        root,
        int_key,
        int,
        leaf_key,
        leaf,
    }
}

fn chain_err(r: Result<Vec<Certificate>, Error>) -> &'static str {
    match r {
        Err(Error::InvalidChain(why)) => why,
        other => panic!("expected a chain error, got {other:?}"),
    }
}

#[test]
fn keys_round_trip_in_standard_encodings() {
    for alg in [Algorithm::MlDsa65, Algorithm::MlDsa87] {
        let k = PrivateKey::generate(alg).unwrap();
        let pem = k.to_pkcs8_pem();
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----\n"));
        let back = PrivateKey::from_pkcs8_pem(&pem).unwrap();
        assert_eq!(back.public_key(), k.public_key());
        assert_eq!(k.to_pkcs8_der().len(), 54, "seed-only PKCS#8 is 54 bytes");
        let spki = k.public_key().to_spki_pem();
        assert_eq!(PublicKey::from_spki_pem(&spki).unwrap(), *k.public_key());
        let sig = k.sign(b"m").unwrap();
        k.public_key().verify(b"m", &sig).unwrap();
        assert_eq!(k.public_key().verify(b"x", &sig), Err(Error::BadSignature));
    }
}

#[test]
fn malformed_keys_are_rejected() {
    let k = PrivateKey::from_seed(Algorithm::MlDsa65, &[5; 32]);
    let der = k.to_pkcs8_der();
    for i in 0..der.len() {
        let mut bad = der.to_vec();
        bad[i] ^= 0x01;
        // Still valid keys, legitimately: any seed bit (another key), version 0 -> 1
        // (OneAsymmetricKey v2, RFC 5958) and the last OID byte 0x12 -> 0x13 (ML-DSA-87 from the
        // same seed). Every other byte must be rejected.
        let seed_range = der.len() - 32..der.len();
        if !seed_range.contains(&i) && i != 4 && i != 17 {
            assert!(PrivateKey::from_pkcs8_der(&bad).is_err(), "byte {i}");
        }
    }
    let mut trailing = der.to_vec();
    trailing.push(0);
    assert!(PrivateKey::from_pkcs8_der(&trailing).is_err());
    assert!(
        PrivateKey::from_pkcs8_pem("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n")
            .is_err()
    );
    let spki = k.public_key().to_spki_der();
    assert!(PublicKey::from_spki_der(&spki[..spki.len() - 1]).is_err());
    assert!(PublicKey::from_raw(Algorithm::MlDsa87, k.public_key().as_raw()).is_err());
}

#[test]
fn valid_chains_verify() {
    for alg in [Algorithm::MlDsa65, Algorithm::MlDsa87] {
        let p = pki(alg);
        let path = verify_chain(
            &p.leaf,
            std::slice::from_ref(&p.int),
            std::slice::from_ref(&p.root),
            &VerifyOptions::for_dns_name("svc.example.com"),
        )
        .unwrap();
        assert_eq!(path, vec![p.leaf.clone(), p.int.clone(), p.root.clone()]);
        verify_chain(
            &p.leaf,
            std::slice::from_ref(&p.int),
            std::slice::from_ref(&p.root),
            &VerifyOptions::for_dns_name("a.svc.example.com"),
        )
        .unwrap();
        // The intermediate itself as trust anchor.
        verify_chain(
            &p.leaf,
            &[],
            std::slice::from_ref(&p.int),
            &VerifyOptions::default(),
        )
        .unwrap();
        // Irrelevant extra intermediates and anchors are ignored.
        let other = pki(alg);
        verify_chain(
            &p.leaf,
            &[other.int.clone(), p.int.clone()],
            &[other.root.clone(), p.root.clone()],
            &VerifyOptions::default(),
        )
        .unwrap();
        let _ = (&p.root_key, &p.int_key, &p.leaf_key);
    }
}

#[test]
fn chain_rejections() {
    let p = pki(Algorithm::MlDsa65);
    let (i, r) = (std::slice::from_ref(&p.int), std::slice::from_ref(&p.root));
    let at = |t: i64| VerifyOptions {
        now: Some(t),
        ..VerifyOptions::default()
    };
    assert_eq!(
        chain_err(verify_chain(&p.leaf, &[], r, &VerifyOptions::default())),
        "no path to a trust anchor"
    );
    assert_eq!(
        chain_err(verify_chain(&p.leaf, i, &[], &VerifyOptions::default())),
        "no path to a trust anchor"
    );
    assert_eq!(
        chain_err(verify_chain(&p.leaf, i, r, &at(now() + 31 * DAY))),
        "certificate expired"
    );
    assert_eq!(
        chain_err(verify_chain(&p.leaf, i, r, &at(now() - DAY))),
        "certificate not yet valid"
    );
    for name in [
        "other.example.com",
        "a.b.svc.example.com",
        "example.com",
        "svc.example.com.evil",
    ] {
        assert_eq!(
            chain_err(verify_chain(
                &p.leaf,
                i,
                r,
                &VerifyOptions::for_dns_name(name)
            )),
            "DNS name not in the leaf's subject alternative names",
            "{name}"
        );
    }
    let client = VerifyOptions {
        purpose: Some(Purpose::ClientAuth),
        ..VerifyOptions::default()
    };
    assert_eq!(
        chain_err(verify_chain(&p.leaf, i, r, &client)),
        "leaf extended key usage does not allow this purpose"
    );
    assert_eq!(
        chain_err(verify_chain(&p.int, &[], r, &VerifyOptions::default())),
        "CA certificate used as an end entity"
    );
    let shallow = VerifyOptions {
        max_depth: 0,
        ..VerifyOptions::default()
    };
    assert!(verify_chain(&p.leaf, i, r, &shallow).is_err());

    // An end-entity key cannot act as a CA; a non-CA cannot issue with the API either.
    assert!(
        CertificateParams::end_entity("x", 1)
            .issue(p.leaf_key.public_key(), &p.leaf, &p.leaf_key)
            .is_err()
    );
    // Issuer key must match the issuer certificate.
    assert!(
        CertificateParams::end_entity("x", 1)
            .issue(p.leaf_key.public_key(), &p.int, &p.root_key)
            .is_err()
    );

    // Path length: root allows one intermediate; a second one below it is rejected.
    let sub_key = PrivateKey::generate(Algorithm::MlDsa65).unwrap();
    let sub = CertificateParams::ca("Sub", 30)
        .issue(sub_key.public_key(), &p.int, &p.int_key)
        .unwrap();
    let deep = CertificateParams::end_entity("deep", 1)
        .issue(p.leaf_key.public_key(), &sub, &sub_key)
        .unwrap();
    assert_eq!(
        chain_err(verify_chain(
            &deep,
            &[sub.clone(), p.int.clone()],
            r,
            &VerifyOptions::default()
        )),
        "path length constraint exceeded"
    );
    verify_chain(
        &deep,
        std::slice::from_ref(&sub),
        i,
        &VerifyOptions::default(),
    )
    .unwrap();

    // Any modified byte breaks the certificate (parse error or signature).
    let der = p.leaf.der().to_vec();
    for pos in (0..der.len()).step_by(37) {
        let mut bad = der.clone();
        bad[pos] ^= 0x01;
        if let Ok(c) = Certificate::from_der(&bad) {
            assert!(
                verify_chain(&c, i, r, &VerifyOptions::default()).is_err(),
                "byte {pos}"
            );
        }
    }
}

#[test]
fn params_are_validated_and_pem_bundles_parse() {
    let k = PrivateKey::generate(Algorithm::MlDsa65).unwrap();
    assert!(CertificateParams::ca("", 1).self_signed(&k).is_err());
    assert!(
        CertificateParams::ca(&"x".repeat(65), 1)
            .self_signed(&k)
            .is_err()
    );
    assert!(CertificateParams::ca("x", 0).self_signed(&k).is_err());
    for bad in [
        "localhost",
        "a..b.com",
        "-a.com",
        "a_b.com",
        "*.*.a.com",
        "a.*.com",
    ] {
        assert!(
            CertificateParams::end_entity("x", 1)
                .dns_names(&[bad])
                .self_signed(&k)
                .is_err(),
            "{bad}"
        );
    }
    assert!(
        CertificateParams::end_entity("x", 1)
            .path_len(1)
            .self_signed(&k)
            .is_err()
    );
    let names = CertificateParams::end_entity("x", 1)
        .dns_names(&["Mixed.Example.COM"])
        .self_signed(&k)
        .unwrap();
    let _ = names;

    let p = pki(Algorithm::MlDsa87);
    let bundle = format!("{}{}", p.int.to_pem(), p.root.to_pem());
    let certs = Certificate::all_from_pem(&bundle).unwrap();
    assert_eq!(certs, vec![p.int.clone(), p.root.clone()]);
    assert!(
        Certificate::from_pem(&bundle).is_err(),
        "more than one block"
    );
    assert_eq!(p.leaf.public_key().unwrap(), *p.leaf_key.public_key());
    assert_eq!(p.root.subject().unwrap(), "CN=Root");
}
