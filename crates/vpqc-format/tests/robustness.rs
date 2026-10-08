//! Robustness: parsers must never panic, over-allocate or accept malformed input.
//! A deterministic mini-fuzzer (random and mutated inputs). Real coverage-guided fuzzing
//! (`cargo-fuzz`) is planned for phase 5.

use vpqc_core::{AeadId, AlgorithmId, KemId, PublicKey, SecretKey, SigId};
use vpqc_format::{
    DetachedSignature, Sealed, armor, dearmor, decode_public_key, decode_secret_key,
    encode_public_key, encode_secret_key,
};

struct Xorshift(u64);

impl Xorshift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next() as u8).collect()
    }
}

fn decode_all(input: &[u8]) {
    let _ = Sealed::decode(input);
    let _ = DetachedSignature::decode(input);
    let _ = decode_public_key(input);
    let _ = decode_secret_key(input);
    if let Ok(s) = std::str::from_utf8(input) {
        let _ = dearmor("VPQC PUBLIC KEY", s);
    }
}

fn valid_samples() -> Vec<Vec<u8>> {
    let pk = PublicKey::new(AlgorithmId::Kem(KemId::XWing), vec![7; 64]);
    let sk = SecretKey::new(AlgorithmId::Kem(KemId::XWing), vec![9; 32]);
    let sealed = Sealed {
        kem: KemId::XWing,
        aead: AeadId::ChaCha20Poly1305,
        kem_ciphertext: vec![1; 50],
        body: vec![2; 40],
    };
    let sig = DetachedSignature {
        algorithm: SigId::Ed25519,
        bytes: vec![3; 64],
    };
    vec![
        encode_public_key(&pk),
        encode_secret_key(&sk),
        sealed.encode(),
        sig.encode(),
        armor("VPQC PUBLIC KEY", &encode_public_key(&pk)).into_bytes(),
    ]
}

#[test]
fn random_inputs_never_panic() {
    let mut rng = Xorshift(0x9e37_79b9_7f4a_7c15);
    for _ in 0..50_000 {
        let len = rng.below(300);
        decode_all(&rng.bytes(len));
    }
    // Inputs that start with a valid magic/version/kind reach deeper parser states.
    for kind in 1..=4u8 {
        for _ in 0..20_000 {
            let mut v = vec![b'V', b'P', b'Q', b'C', 1, kind];
            let len = rng.below(120);
            v.extend(rng.bytes(len));
            decode_all(&v);
        }
    }
}

#[test]
fn mutated_valid_inputs_never_panic_and_rarely_parse() {
    let mut rng = Xorshift(0x1234_5678_9abc_def1);
    for sample in valid_samples() {
        decode_all(&sample);
        for _ in 0..20_000 {
            let mut v = sample.clone();
            for _ in 0..(1 + rng.below(3)) {
                match rng.below(4) {
                    0 if !v.is_empty() => {
                        let i = rng.below(v.len());
                        v[i] ^= 1 << rng.below(8);
                    }
                    1 if !v.is_empty() => {
                        let i = rng.below(v.len());
                        v[i] = rng.next() as u8;
                    }
                    2 => {
                        let n = rng.below(v.len() + 1);
                        v.truncate(n);
                    }
                    _ => v.push(rng.next() as u8),
                }
            }
            decode_all(&v);
        }
    }
}

#[test]
fn extreme_length_fields_are_rejected() {
    // Public key claiming a 4 GiB payload.
    let mut v = vec![b'V', b'P', b'Q', b'C', 1, 3, 0x00, 0x01];
    v.extend_from_slice(&u32::MAX.to_be_bytes());
    v.extend_from_slice(&[0; 8]);
    assert!(decode_public_key(&v).is_err());
    // Signature claiming a 4 GiB payload.
    let mut v = vec![b'V', b'P', b'Q', b'C', 1, 2, 0x01, 0x01];
    v.extend_from_slice(&u32::MAX.to_be_bytes());
    assert!(DetachedSignature::decode(&v).is_err());
    // Sealed box claiming a 64 KiB KEM ciphertext with nothing behind it.
    let mut v = vec![b'V', b'P', b'Q', b'C', 1, 1, 0x00, 0x01, 1, 0xff, 0xff];
    v.extend_from_slice(&[0; 20]);
    assert!(Sealed::decode(&v).is_err());
}

#[test]
fn format_version_and_kind_are_strict() {
    for mut sample in valid_samples() {
        assert!(sample.starts_with(b"VPQC"));
        let original_version = sample[4];
        sample[4] = original_version.wrapping_add(1);
        decode_all(&sample);
        assert!(decode_public_key(&sample).is_err());
        assert!(decode_secret_key(&sample).is_err());
        assert!(Sealed::decode(&sample).is_err());
        assert!(DetachedSignature::decode(&sample).is_err());
    }

    let pk = valid_samples().remove(0);
    let mut wrong_kind = pk.clone();
    wrong_kind[5] = 1; // sealed kind, but the payload is a public key
    assert!(decode_public_key(&wrong_kind).is_err());
    assert!(Sealed::decode(&wrong_kind).is_err());
}

#[test]
fn valid_samples_round_trip() {
    assert!(decode_public_key(&valid_samples()[0]).is_ok());
    assert!(decode_secret_key(&valid_samples()[1]).is_ok());
    assert!(Sealed::decode(&valid_samples()[2]).is_ok());
    assert!(DetachedSignature::decode(&valid_samples()[3]).is_ok());
    let text = String::from_utf8(valid_samples()[4].clone()).unwrap();
    assert!(dearmor("VPQC PUBLIC KEY", &text).is_ok());
    assert!(
        dearmor("VPQC SECRET KEY", &text).is_err(),
        "label must match"
    );
}

#[test]
fn armor_rejects_junk() {
    for text in [
        "",
        "-----BEGIN VPQC PUBLIC KEY-----",
        "-----BEGIN VPQC PUBLIC KEY-----\n!!!\n-----END VPQC PUBLIC KEY-----",
        "garbage\n-----BEGIN VPQC PUBLIC KEY-----\nAAAA\n-----END VPQC PUBLIC KEY-----",
        "-----BEGIN VPQC PUBLIC KEY-----\nAAAA\n-----END VPQC PUBLIC KEY-----\ntrailing",
    ] {
        assert!(dearmor("VPQC PUBLIC KEY", text).is_err(), "{text:?}");
    }
}
