//! Sealed-box encryption behaviour: round trips, tamper detection, key handling.

use vpqc::{AlgorithmId, Error, KemId, Profile, encryption, keys};
use vpqc_core::testing::FixedRandom;

const MSG: &[u8] = b"the quick brown fox jumps over the lazy dog";

#[test]
fn round_trip_all_profiles() {
    for profile in Profile::ALL {
        let kp = encryption::generate(profile).unwrap();
        assert_eq!(kp.public.algorithm(), AlgorithmId::Kem(profile.kem()));
        let sealed = encryption::seal(&kp.public, MSG, b"ctx").unwrap();
        assert_eq!(
            encryption::open(&kp.secret, &sealed, b"ctx").unwrap(),
            MSG,
            "{profile:?}"
        );
    }
}

#[test]
fn empty_and_large_plaintext() {
    let kp = encryption::generate(Profile::Standard).unwrap();
    let sealed = encryption::seal(&kp.public, b"", b"").unwrap();
    assert_eq!(encryption::open(&kp.secret, &sealed, b"").unwrap(), b"");
    let big = vec![0xa5u8; 1 << 20];
    let sealed = encryption::seal(&kp.public, &big, b"").unwrap();
    assert_eq!(encryption::open(&kp.secret, &sealed, b"").unwrap(), big);
}

#[test]
fn wrong_key_fails() {
    for profile in Profile::ALL {
        let a = encryption::generate(profile).unwrap();
        let b = encryption::generate(profile).unwrap();
        let sealed = encryption::seal(&a.public, MSG, b"").unwrap();
        assert_eq!(
            encryption::open(&b.secret, &sealed, b""),
            Err(Error::DecryptionFailed)
        );
    }
}

#[test]
fn wrong_aad_fails() {
    let kp = encryption::generate(Profile::Standard).unwrap();
    let sealed = encryption::seal(&kp.public, MSG, b"invoice-42").unwrap();
    assert_eq!(
        encryption::open(&kp.secret, &sealed, b"invoice-43"),
        Err(Error::DecryptionFailed)
    );
    assert_eq!(
        encryption::open(&kp.secret, &sealed, b""),
        Err(Error::DecryptionFailed)
    );
}

#[test]
fn key_of_other_algorithm_is_rejected() {
    let std = encryption::generate(Profile::Standard).unwrap();
    let cnsa = encryption::generate(Profile::Cnsa2).unwrap();
    let sealed = encryption::seal(&std.public, MSG, b"").unwrap();
    assert_eq!(
        encryption::open(&cnsa.secret, &sealed, b""),
        Err(Error::AlgorithmMismatch)
    );
}

#[test]
fn signing_key_cannot_encrypt() {
    let sig = vpqc::signing::generate(Profile::Standard).unwrap();
    assert_eq!(
        encryption::seal(&sig.public, MSG, b"").unwrap_err(),
        Error::AlgorithmMismatch
    );
}

/// Flipping any single bit of the envelope, at every byte position, must never yield
/// a successful decryption. This covers header fields, the KEM ciphertext, the
/// ciphertext body and the tag.
#[test]
fn every_single_byte_flip_is_rejected() {
    let kp = encryption::generate(Profile::Standard).unwrap();
    let sealed = encryption::seal(&kp.public, MSG, b"ctx").unwrap();
    for i in 0..sealed.len() {
        let mut bad = sealed.clone();
        bad[i] ^= 0x01;
        assert!(
            encryption::open(&kp.secret, &bad, b"ctx").is_err(),
            "flip at byte {i} was accepted"
        );
    }
}

#[test]
fn every_truncation_is_rejected_without_panic() {
    let kp = encryption::generate(Profile::Standard).unwrap();
    let sealed = encryption::seal(&kp.public, MSG, b"").unwrap();
    for len in 0..sealed.len() {
        assert!(
            encryption::open(&kp.secret, &sealed[..len], b"").is_err(),
            "len {len}"
        );
    }
    let mut extended = sealed.clone();
    extended.push(0);
    assert!(encryption::open(&kp.secret, &extended, b"").is_err());
}

#[test]
fn garbage_input_is_rejected() {
    let kp = encryption::generate(Profile::Standard).unwrap();
    for junk in [&b""[..], b"VPQC", b"not a sealed box at all", &[0u8; 2000]] {
        assert!(encryption::open(&kp.secret, junk, b"").is_err());
    }
}

#[test]
fn sealing_is_randomized() {
    let kp = encryption::generate(Profile::Standard).unwrap();
    let a = encryption::seal(&kp.public, MSG, b"").unwrap();
    let b = encryption::seal(&kp.public, MSG, b"").unwrap();
    assert_ne!(a, b);
}

#[test]
fn deterministic_with_fixed_randomness() {
    let rand: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
    let k1 = encryption::generate_with(Profile::Standard, &mut FixedRandom::new(&rand)).unwrap();
    let k2 = encryption::generate_with(Profile::Standard, &mut FixedRandom::new(&rand)).unwrap();
    assert_eq!(k1.public, k2.public);
    let s1 =
        encryption::seal_with(&k1.public, MSG, b"", &mut FixedRandom::new(&rand[100..])).unwrap();
    let s2 =
        encryption::seal_with(&k1.public, MSG, b"", &mut FixedRandom::new(&rand[100..])).unwrap();
    assert_eq!(s1, s2);
    assert_eq!(encryption::open(&k1.secret, &s1, b"").unwrap(), MSG);
}

#[test]
fn rng_failure_is_reported() {
    let err = encryption::generate_with(Profile::Standard, &mut FixedRandom::new(&[1, 2, 3]));
    assert_eq!(err.unwrap_err(), Error::Rng);
}

#[test]
fn key_serialization_round_trip() {
    let kp = encryption::generate(Profile::Standard).unwrap();
    assert_eq!(
        keys::public_from_bytes(&keys::public_to_bytes(&kp.public)).unwrap(),
        kp.public
    );
    assert_eq!(
        keys::public_from_text(&keys::public_to_text(&kp.public)).unwrap(),
        kp.public
    );

    let sk = keys::secret_from_text(&keys::secret_to_text(&kp.secret)).unwrap();
    let sealed = encryption::seal(&kp.public, MSG, b"").unwrap();
    assert_eq!(encryption::open(&sk, &sealed, b"").unwrap(), MSG);
}

#[test]
fn key_serialization_rejects_corruption() {
    let kp = encryption::generate(Profile::Standard).unwrap();
    let bytes = keys::public_to_bytes(&kp.public);
    for i in 0..bytes.len() {
        let mut bad = bytes.clone();
        bad[i] ^= 0x80;
        assert!(keys::public_from_bytes(&bad).is_err(), "byte {i}");
    }
    for len in 0..bytes.len() {
        assert!(keys::public_from_bytes(&bytes[..len]).is_err());
    }
    // A public key is not a secret key and vice versa.
    assert!(keys::secret_from_bytes(&bytes).is_err());
    assert!(keys::public_from_text(&keys::secret_to_text(&kp.secret)).is_err());
}

#[test]
fn secret_and_shared_secret_debug_is_redacted() {
    let kp = encryption::generate(Profile::Standard).unwrap();
    let dbg = format!("{:?}", kp.secret);
    assert!(dbg.contains("redacted"));
    let (_ct, ss) = vpqc::kem(KemId::XWing)
        .unwrap()
        .encapsulate(&kp.public, &mut vpqc::OsRng)
        .unwrap();
    assert!(format!("{ss:?}").contains("redacted"));
}

/// ML-KEM implicit rejection: a corrupted ciphertext yields a different shared secret
/// (not an error), and opening then fails at the AEAD tag.
#[test]
fn kem_implicit_rejection() {
    for id in [KemId::XWing, KemId::MlKem768, KemId::MlKem1024] {
        let kem = vpqc::kem(id).unwrap();
        let kp = kem.generate(&mut vpqc::OsRng).unwrap();
        let (mut ct, ss) = kem.encapsulate(&kp.public, &mut vpqc::OsRng).unwrap();
        assert_eq!(
            kem.decapsulate(&kp.secret, &ct).unwrap().expose(),
            ss.expose()
        );
        ct[3] ^= 1;
        let bad = kem.decapsulate(&kp.secret, &ct).unwrap();
        assert_ne!(bad.expose(), ss.expose(), "{id:?}");
        assert!(kem.decapsulate(&kp.secret, &ct[..ct.len() - 1]).is_err());
    }
}

#[test]
fn invalid_public_key_is_rejected() {
    // ML-KEM encapsulation-key check (FIPS 203 section 7.2): a coefficient >= q is invalid.
    let kem = vpqc::kem(KemId::MlKem768).unwrap();
    let kp = kem.generate(&mut vpqc::OsRng).unwrap();
    let mut bytes = kp.public.as_bytes().to_vec();
    bytes[0] = 0xff;
    bytes[1] |= 0x0f; // first 12-bit coefficient becomes 0xfff = 4095 > 3328
    let bad = vpqc::PublicKey::new(kp.public.algorithm(), bytes);
    assert!(kem.encapsulate(&bad, &mut vpqc::OsRng).is_err());
    let short = vpqc::PublicKey::new(kp.public.algorithm(), vec![0; 10]);
    assert!(kem.encapsulate(&short, &mut vpqc::OsRng).is_err());
}

#[test]
fn high_profile_kem_properties() {
    let kem = vpqc::kem(KemId::MlKem1024P384).unwrap();
    let kp = kem.generate(&mut vpqc::OsRng).unwrap();
    assert_eq!(kp.public.as_bytes().len(), 1665);
    let (ct, ss) = kem.encapsulate(&kp.public, &mut vpqc::OsRng).unwrap();
    assert_eq!(ct.len(), 1665);
    assert_eq!(
        kem.decapsulate(&kp.secret, &ct).unwrap().expose(),
        ss.expose()
    );

    // A ciphertext whose P-384 point is not on the curve is rejected explicitly.
    let mut bad = ct.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    assert!(kem.decapsulate(&kp.secret, &bad).is_err());
    // Corrupting the ML-KEM part yields a different secret (implicit rejection).
    let mut bad = ct.clone();
    bad[5] ^= 1;
    assert_ne!(
        kem.decapsulate(&kp.secret, &bad).unwrap().expose(),
        ss.expose()
    );

    // Public key with an off-curve point is rejected at encapsulation.
    let mut pk = kp.public.as_bytes().to_vec();
    let last = pk.len() - 1;
    pk[last] ^= 1;
    let bad_pk = vpqc::PublicKey::new(kp.public.algorithm(), pk);
    assert!(kem.encapsulate(&bad_pk, &mut vpqc::OsRng).is_err());

    // End-to-end through the sealed box.
    let keys = encryption::generate(Profile::High).unwrap();
    let sealed = encryption::seal(&keys.public, MSG, b"").unwrap();
    assert_eq!(encryption::open(&keys.secret, &sealed, b"").unwrap(), MSG);
}
