//! Signature behaviour: contexts, composite semantics, downgrade resistance.

use vpqc::{AlgorithmId, Error, Profile, SigId, signing};
use vpqc_core::testing::FixedRandom;
use vpqc_format::DetachedSignature;

const MSG: &[u8] = b"release-1.0.tar.gz";
const CTX: &[u8] = b"my-app/release-v1";

#[test]
fn round_trip_all_profiles() {
    for profile in Profile::ALL {
        let kp = signing::generate(profile).unwrap();
        assert_eq!(kp.public.algorithm(), AlgorithmId::Sig(profile.signature()));
        let sig = signing::sign(&kp.secret, MSG, CTX).unwrap();
        signing::verify(&kp.public, MSG, CTX, &sig).unwrap_or_else(|e| panic!("{profile:?}: {e}"));
    }
}

#[test]
fn wrong_message_context_or_key_fails() {
    for profile in Profile::ALL {
        let kp = signing::generate(profile).unwrap();
        let other = signing::generate(profile).unwrap();
        let sig = signing::sign(&kp.secret, MSG, CTX).unwrap();
        assert_eq!(
            signing::verify(&kp.public, b"other", CTX, &sig),
            Err(Error::VerificationFailed)
        );
        assert_eq!(
            signing::verify(&kp.public, MSG, b"other", &sig),
            Err(Error::VerificationFailed)
        );
        assert_eq!(
            signing::verify(&kp.public, MSG, b"", &sig),
            Err(Error::VerificationFailed)
        );
        assert_eq!(
            signing::verify(&other.public, MSG, CTX, &sig),
            Err(Error::VerificationFailed)
        );
    }
}

#[test]
fn context_length_limit() {
    let kp = signing::generate(Profile::Standard).unwrap();
    let long = vec![7u8; 256];
    assert_eq!(
        signing::sign(&kp.secret, MSG, &long).unwrap_err(),
        Error::ContextTooLong
    );
    let ok = vec![7u8; 255];
    let sig = signing::sign(&kp.secret, MSG, &ok).unwrap();
    signing::verify(&kp.public, MSG, &ok, &sig).unwrap();
}

#[test]
fn bit_flips_and_truncation_are_rejected() {
    let kp = signing::generate(Profile::Standard).unwrap();
    let sig = signing::sign(&kp.secret, MSG, CTX).unwrap();
    // Header, Ed25519 half start/end, ML-DSA half start/middle/end.
    let positions = [
        0,
        5,
        7,
        12,
        13,
        40,
        75,
        76,
        77,
        500,
        2000,
        sig.len() - 2,
        sig.len() - 1,
    ];
    for &i in &positions {
        let mut bad = sig.clone();
        bad[i] ^= 0x01;
        assert!(
            signing::verify(&kp.public, MSG, CTX, &bad).is_err(),
            "flip at {i}"
        );
    }
    for len in [0, 1, 11, 12, 13, 100, sig.len() - 1] {
        assert!(
            signing::verify(&kp.public, MSG, CTX, &sig[..len]).is_err(),
            "len {len}"
        );
    }
    let mut extended = sig.clone();
    extended.push(0);
    assert!(signing::verify(&kp.public, MSG, CTX, &extended).is_err());
}

/// The composite needs *both* signatures. Breaking either half alone must fail.
#[test]
fn composite_requires_both_halves() {
    let kp = signing::generate(Profile::Standard).unwrap();
    let sig = signing::sign(&kp.secret, MSG, CTX).unwrap();
    let parsed = DetachedSignature::decode(&sig).unwrap();
    assert_eq!(parsed.algorithm, SigId::Ed25519MlDsa65);
    assert_eq!(parsed.bytes.len(), 64 + 3309);

    let mut bad_ed = parsed.clone();
    bad_ed.bytes[10] ^= 1;
    assert!(signing::verify(&kp.public, MSG, CTX, &bad_ed.encode()).is_err());

    let mut bad_ml = parsed.clone();
    bad_ml.bytes[64 + 10] ^= 1;
    assert!(signing::verify(&kp.public, MSG, CTX, &bad_ml.encode()).is_err());

    // Zeroing one half entirely also fails.
    let mut no_ml = parsed.clone();
    no_ml.bytes[64..].fill(0);
    assert!(signing::verify(&kp.public, MSG, CTX, &no_ml.encode()).is_err());
    let mut no_ed = parsed;
    no_ed.bytes[..64].fill(0);
    assert!(signing::verify(&kp.public, MSG, CTX, &no_ed.encode()).is_err());
}

/// Downgrade attacks: a signature cannot be re-labelled as another algorithm.
#[test]
fn algorithm_relabelling_is_rejected() {
    let comp = signing::generate(Profile::Standard).unwrap();
    let sig = signing::sign(&comp.secret, MSG, CTX).unwrap();
    let parsed = DetachedSignature::decode(&sig).unwrap();

    // Relabel the composite as plain ML-DSA-65 / Ed25519: rejected by the key check.
    for alg in [SigId::MlDsa65, SigId::Ed25519, SigId::MlDsa87] {
        let relabelled = DetachedSignature {
            algorithm: alg,
            bytes: parsed.bytes.clone(),
        }
        .encode();
        assert!(signing::verify(&comp.public, MSG, CTX, &relabelled).is_err());
    }

    // Strip the composite to its Ed25519 half and verify with the Ed25519 component key:
    // the domain-separated representative differs, so it must fail.
    let ed_pk = vpqc::PublicKey::new(
        AlgorithmId::Sig(SigId::Ed25519),
        comp.public.as_bytes()[..32].to_vec(),
    );
    let stripped = DetachedSignature {
        algorithm: SigId::Ed25519,
        bytes: parsed.bytes[..64].to_vec(),
    }
    .encode();
    assert!(signing::verify(&ed_pk, MSG, CTX, &stripped).is_err());

    // Same for the ML-DSA half.
    let ml_pk = vpqc::PublicKey::new(
        AlgorithmId::Sig(SigId::MlDsa65),
        comp.public.as_bytes()[32..].to_vec(),
    );
    let stripped = DetachedSignature {
        algorithm: SigId::MlDsa65,
        bytes: parsed.bytes[64..].to_vec(),
    }
    .encode();
    assert!(signing::verify(&ml_pk, MSG, CTX, &stripped).is_err());
}

#[test]
fn encryption_key_cannot_sign() {
    let kp = vpqc::encryption::generate(Profile::Standard).unwrap();
    assert_eq!(
        signing::sign(&kp.secret, MSG, CTX).unwrap_err(),
        Error::AlgorithmMismatch
    );
}

#[test]
fn deterministic_keys_and_hedged_signatures() {
    let rand: Vec<u8> = (0..=255u8).cycle().take(2048).collect();
    let k1 = signing::generate_with(Profile::Standard, &mut FixedRandom::new(&rand)).unwrap();
    let k2 = signing::generate_with(Profile::Standard, &mut FixedRandom::new(&rand)).unwrap();
    assert_eq!(k1.public, k2.public);
    // Signing is hedged: different randomness gives different (both valid) signatures.
    let s1 = signing::sign_with(&k1.secret, MSG, CTX, &mut FixedRandom::new(&[1; 64])).unwrap();
    let s2 = signing::sign_with(&k1.secret, MSG, CTX, &mut FixedRandom::new(&[2; 64])).unwrap();
    assert_ne!(s1, s2);
    signing::verify(&k1.public, MSG, CTX, &s1).unwrap();
    signing::verify(&k1.public, MSG, CTX, &s2).unwrap();
}

#[test]
fn ml_dsa_variants_round_trip() {
    for id in [
        SigId::MlDsa65,
        SigId::MlDsa87,
        SigId::Ed25519,
        SigId::Ed25519MlDsa65,
    ] {
        let scheme = vpqc::signature_scheme(id).unwrap();
        let (pk, sk) = scheme.generate(&mut vpqc::OsRng).unwrap();
        let sig = scheme.sign(&sk, MSG, CTX, &mut vpqc::OsRng).unwrap();
        assert_eq!(sig.len(), scheme.signature_len(), "{id:?}");
        scheme.verify(&pk, MSG, CTX, &sig).unwrap();
        assert!(scheme.verify(&pk, MSG, b"x", &sig).is_err());
    }
}
