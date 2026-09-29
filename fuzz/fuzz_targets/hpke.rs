//! HPKE: `open` never panics on hostile `enc`/ciphertext; single-shot round trip for every
//! supported suite and any info/aad/plaintext.
#![no_main]
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use vpqc_fuzz::Input;
use vpqc_hpke::{Aead, Kdf, Kem, Suite, derive_key_pair};

fn keys() -> &'static [(Kem, Vec<u8>, Vec<u8>)] {
    static K: OnceLock<Vec<(Kem, Vec<u8>, Vec<u8>)>> = OnceLock::new();
    K.get_or_init(|| {
        [Kem::XWing, Kem::MlKem1024P384, Kem::MlKem768, Kem::MlKem1024]
            .into_iter()
            .map(|kem| {
                let (sk, pk) = derive_key_pair(kem, b"vpqc fuzz hpke ikm, 32+ bytes....").unwrap();
                (kem, sk.to_vec(), pk)
            })
            .collect()
    })
}

fuzz_target!(|data: &[u8]| {
    let mut input = Input(data);
    let mode = input.byte();
    let (kem, sk, pk) = &keys()[(input.byte() % 4) as usize];
    let kdf = [Kdf::HkdfSha256, Kdf::HkdfSha384, Kdf::HkdfSha512, Kdf::Shake128, Kdf::Shake256][(input.byte() % 5) as usize];
    let aead = [Aead::Aes128Gcm, Aead::Aes256Gcm, Aead::ChaCha20Poly1305][(input.byte() % 3) as usize];
    let suite = Suite { kem: *kem, kdf, aead };
    let info = input.slice();
    let aad = input.slice();
    let rest = input.rest();
    if mode & 1 == 0 {
        let split = rest.len().min(kem.n_enc());
        let _ = vpqc_hpke::open(suite, &rest[..split], sk, info, aad, &rest[split..]);
    } else {
        let (enc, ct) = vpqc_hpke::seal(suite, pk, info, aad, rest).unwrap();
        assert_eq!(vpqc_hpke::open(suite, &enc, sk, info, aad, &ct).unwrap(), rest);
        let mut bad = ct.clone();
        let i = (mode as usize + rest.len()) % bad.len();
        bad[i] ^= 1;
        assert!(vpqc_hpke::open(suite, &enc, sk, info, aad, &bad).is_err());
    }
});
