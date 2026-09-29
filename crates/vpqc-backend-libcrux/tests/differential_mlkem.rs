//! Differential test: libcrux (verified) vs RustCrypto `ml-kem` (independent, pure Rust).
//! Same seed and randomness must give byte-identical keys, ciphertexts and shared secrets.

use ml_kem::kem::{Decapsulate, KeyExport};
use ml_kem::{DecapsulationKey768, DecapsulationKey1024};
use vpqc_backend_libcrux::mlkem::{self, Level};

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).unwrap();
    b
}

macro_rules! differential {
    ($name:ident, $rc:ty, $level:expr) => {
        #[test]
        fn $name() {
            for _ in 0..25 {
                let seed: [u8; 64] = random();
                let m: [u8; 32] = random();

                let ours = mlkem::keygen($level, &seed);
                let dk = <$rc>::from_seed(seed.into());
                let ek = dk.encapsulation_key();
                assert_eq!(
                    ours.public.as_slice(),
                    ek.to_bytes().as_slice(),
                    "public key"
                );

                let (our_ct, our_ss) = mlkem::encapsulate($level, &ours.public, &m).unwrap();
                let (rc_ct, rc_ss) = ek.encapsulate_deterministic(&m.into());
                assert_eq!(our_ct.as_slice(), rc_ct.as_slice(), "ciphertext");
                assert_eq!(our_ss.as_slice(), rc_ss.as_slice(), "encapsulated secret");

                // Cross-decapsulate.
                let ours_dec = mlkem::decapsulate($level, &ours.decapsulation_key, &rc_ct).unwrap();
                assert_eq!(ours_dec.as_slice(), rc_ss.as_slice());
                let rc_dec = dk.decapsulate(&our_ct.as_slice().try_into().unwrap());
                assert_eq!(rc_dec.as_slice(), our_ss.as_slice());

                // Implicit rejection must also agree on a corrupted ciphertext.
                let mut bad = our_ct.clone();
                bad[7] ^= 0x40;
                let a = mlkem::decapsulate($level, &ours.decapsulation_key, &bad).unwrap();
                let b = dk.decapsulate(&bad.as_slice().try_into().unwrap());
                assert_eq!(a.as_slice(), b.as_slice(), "implicit rejection output");
            }
        }
    };
}

differential!(
    mlkem768_matches_rustcrypto,
    DecapsulationKey768,
    Level::L768
);
differential!(
    mlkem1024_matches_rustcrypto,
    DecapsulationKey1024,
    Level::L1024
);
