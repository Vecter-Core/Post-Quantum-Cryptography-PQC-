//! Behavioural tests: round trips, tampering, modes, limits.

use vpqc_core::Error;
use vpqc_hpke::{
    Aead, Kdf, Kem, Suite, generate_key_pair, open, seal, setup_base_r, setup_base_s, setup_psk_r,
    setup_psk_s,
};

fn suites() -> Vec<Suite> {
    let mut v = Vec::new();
    for kem in [
        Kem::XWing,
        Kem::MlKem1024P384,
        Kem::MlKem768,
        Kem::MlKem1024,
    ] {
        for kdf in [
            Kdf::HkdfSha256,
            Kdf::HkdfSha384,
            Kdf::HkdfSha512,
            Kdf::Shake128,
            Kdf::Shake256,
        ] {
            for aead in [Aead::Aes128Gcm, Aead::Aes256Gcm, Aead::ChaCha20Poly1305] {
                v.push(Suite { kem, kdf, aead });
            }
        }
    }
    v
}

#[test]
fn single_shot_round_trip_all_suites() {
    for suite in suites() {
        let (sk, pk) = generate_key_pair(suite.kem).unwrap();
        let (enc, ct) = seal(suite, &pk, b"info", b"aad", b"hello").unwrap();
        assert_eq!(
            open(suite, &enc, &sk, b"info", b"aad", &ct).unwrap(),
            b"hello",
            "{suite:?}"
        );
        assert_eq!(
            open(suite, &enc, &sk, b"other", b"aad", &ct),
            Err(Error::DecryptionFailed)
        );
        assert_eq!(
            open(suite, &enc, &sk, b"info", b"other", &ct),
            Err(Error::DecryptionFailed)
        );
    }
}

#[test]
fn tampering_and_wrong_key_fail() {
    let suite = Suite::DEFAULT;
    let (sk, pk) = generate_key_pair(suite.kem).unwrap();
    let (sk2, _) = generate_key_pair(suite.kem).unwrap();
    let (enc, ct) = seal(suite, &pk, b"", b"", b"message").unwrap();
    assert!(open(suite, &enc, &sk2, b"", b"", &ct).is_err());
    for i in [0, 100, enc.len() - 1] {
        let mut e = enc.clone();
        e[i] ^= 1;
        assert!(open(suite, &e, &sk, b"", b"", &ct).is_err(), "enc byte {i}");
    }
    for i in 0..ct.len() {
        let mut c = ct.clone();
        c[i] ^= 1;
        assert!(open(suite, &enc, &sk, b"", b"", &c).is_err(), "ct byte {i}");
    }
    assert!(open(suite, &enc[..enc.len() - 1], &sk, b"", b"", &ct).is_err());
}

#[test]
fn multi_message_context_and_ordering() {
    let suite = Suite::HIGH;
    let (sk, pk) = generate_key_pair(suite.kem).unwrap();
    let (enc, mut s) = setup_base_s(suite, &pk, b"stream").unwrap();
    let mut r = setup_base_r(suite, &enc, &sk, b"stream").unwrap();
    let c0 = s.seal(b"", b"zero").unwrap();
    let c1 = s.seal(b"", b"one").unwrap();
    assert_ne!(c0, c1);
    // Out-of-order delivery fails: nonces are bound to the sequence number.
    assert!(r.open(b"", &c1).is_err());
    assert_eq!(r.sequence(), 0, "failed open must not advance the sequence");
    assert_eq!(r.open(b"", &c0).unwrap(), b"zero");
    assert_eq!(r.open(b"", &c1).unwrap(), b"one");
    // Both sides export the same secret.
    assert_eq!(
        *s.export(b"ctx", 42).unwrap(),
        *r.export(b"ctx", 42).unwrap()
    );
    assert_ne!(
        *s.export(b"ctx", 42).unwrap(),
        *r.export(b"other", 42).unwrap()
    );
}

#[test]
fn psk_mode() {
    let suite = Suite::DEFAULT;
    let psk = [7u8; 32];
    let (sk, pk) = generate_key_pair(suite.kem).unwrap();
    let (enc, mut s) = setup_psk_s(suite, &pk, b"i", &psk, b"id-1").unwrap();
    let ct = s.seal(b"", b"x").unwrap();
    let mut r = setup_psk_r(suite, &enc, &sk, b"i", &psk, b"id-1").unwrap();
    assert_eq!(r.open(b"", &ct).unwrap(), b"x");
    let mut wrong = setup_psk_r(suite, &enc, &sk, b"i", &[8u8; 32], b"id-1").unwrap();
    assert!(wrong.open(b"", &ct).is_err());
    let mut base = setup_base_r(suite, &enc, &sk, b"i").unwrap();
    assert!(base.open(b"", &ct).is_err(), "PSK and base contexts differ");
    // Input validation.
    assert!(
        setup_psk_s(suite, &pk, b"", &[1u8; 16], b"id").is_err(),
        "short PSK"
    );
    assert!(
        setup_psk_s(suite, &pk, b"", &psk, b"").is_err(),
        "missing psk_id"
    );
}

#[test]
fn export_only_suite() {
    let suite = Suite {
        kem: Kem::XWing,
        kdf: Kdf::HkdfSha256,
        aead: Aead::ExportOnly,
    };
    let (sk, pk) = generate_key_pair(suite.kem).unwrap();
    let (enc, mut s) = setup_base_s(suite, &pk, b"").unwrap();
    let r = setup_base_r(suite, &enc, &sk, b"").unwrap();
    assert_eq!(*s.export(b"k", 32).unwrap(), *r.export(b"k", 32).unwrap());
    assert!(s.seal(b"", b"x").is_err());
    assert!(seal(suite, &pk, b"", b"", b"x").is_err());
}

#[test]
fn length_limits() {
    let (sk, pk) = generate_key_pair(Kem::XWing).unwrap();
    let hkdf = Suite::DEFAULT;
    let (enc, s) = setup_base_s(hkdf, &pk, b"").unwrap();
    assert!(s.export(b"", 255 * 32).is_ok());
    assert!(s.export(b"", 255 * 32 + 1).is_err());
    let shake = Suite {
        kdf: Kdf::Shake256,
        ..hkdf
    };
    let (_, s) = setup_base_s(shake, &pk, b"").unwrap();
    assert!(s.export(b"", 65535).is_ok());
    assert!(s.export(b"", 65536).is_err());
    // Oversized info is rejected by single-stage KDFs, not truncated.
    assert!(setup_base_s(shake, &pk, &vec![0u8; 70_000]).is_err());
    let _ = (sk, enc);
}

#[test]
fn wrong_key_sizes_are_rejected() {
    let suite = Suite::DEFAULT;
    assert!(seal(suite, &[0u8; 10], b"", b"", b"x").is_err());
    let (_, pk) = generate_key_pair(Kem::MlKem768).unwrap();
    assert!(
        seal(suite, &pk, b"", b"", b"x").is_err(),
        "ML-KEM key used with X-Wing suite"
    );
    assert!(
        Suite::from_ids(0x0020, 1, 1).is_err(),
        "classical DHKEM not offered"
    );
}
