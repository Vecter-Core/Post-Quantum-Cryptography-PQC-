//! Differential test: libcrux (verified) vs RustCrypto `ml-dsa` (independent, pure Rust).
//! Same seed must give identical keys; deterministic signing (`rnd = 0^32`) must give
//! byte-identical signatures; each backend must verify the other's signatures.

use ml_dsa::{Keypair, MlDsa65, MlDsa87, SigningKey};
use vpqc_backend_libcrux::mldsa::{self, Level};

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).unwrap();
    b
}

macro_rules! differential {
    ($name:ident, $rc:ty, $level:expr) => {
        #[test]
        #[allow(deprecated)] // `to_expanded` is the only way to compare expanded key bytes
        fn $name() {
            for i in 0..10u8 {
                let seed: [u8; 32] = random();
                let msg: Vec<u8> = (0..(i as usize * 37)).map(|x| x as u8 ^ i).collect();
                let ctx = vec![i; (i as usize) % 4];

                let rc_sk = SigningKey::<$rc>::from_seed(&seed.into());
                let rc_vk = rc_sk.verifying_key();
                let (our_vk, our_sk) = mldsa::keygen($level, &seed);
                assert_eq!(
                    our_vk.as_slice(),
                    rc_vk.encode().as_slice(),
                    "verification key"
                );
                assert_eq!(
                    our_sk.as_slice(),
                    rc_sk.expanded_key().to_expanded().as_slice(),
                    "expanded signing key"
                );

                // Deterministic signatures are identical.
                let our_sig = mldsa::sign($level, &our_sk, &msg, &ctx, &[0u8; 32]).unwrap();
                let rc_sig = rc_sk.expanded_key().sign_deterministic(&msg, &ctx).unwrap();
                assert_eq!(our_sig.as_slice(), rc_sig.encode().as_slice(), "signature");

                // Cross verification.
                mldsa::verify(
                    $level,
                    rc_vk.encode().as_slice(),
                    &msg,
                    &ctx,
                    rc_sig.encode().as_slice(),
                )
                .expect("libcrux rejected RustCrypto signature");
                let parsed =
                    ml_dsa::Signature::<$rc>::decode(&our_sig.as_slice().try_into().unwrap())
                        .expect("RustCrypto could not parse libcrux signature");
                assert!(
                    rc_vk.verify_with_context(&msg, &ctx, &parsed),
                    "RustCrypto rejected libcrux signature"
                );

                // Hedged (randomized) libcrux signature must verify in RustCrypto too.
                let hedged = mldsa::sign($level, &our_sk, &msg, &ctx, &random()).unwrap();
                let parsed =
                    ml_dsa::Signature::<$rc>::decode(&hedged.as_slice().try_into().unwrap())
                        .unwrap();
                assert!(rc_vk.verify_with_context(&msg, &ctx, &parsed));

                // Both reject a wrong context and a modified message.
                let mut bad_ctx = ctx.clone();
                bad_ctx.push(0xEE);
                assert!(mldsa::verify($level, &our_vk, &msg, &bad_ctx, &our_sig).is_err());
                assert!(!rc_vk.verify_with_context(&msg, &bad_ctx, &parsed));
                let mut bad_msg = msg.clone();
                bad_msg.push(1);
                assert!(mldsa::verify($level, &our_vk, &bad_msg, &ctx, &our_sig).is_err());
            }
        }
    };
}

differential!(mldsa65_matches_rustcrypto, MlDsa65, Level::L65);
differential!(mldsa87_matches_rustcrypto, MlDsa87, Level::L87);
