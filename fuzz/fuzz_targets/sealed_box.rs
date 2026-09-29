//! Sealed box: `open` never panics on hostile input; seal/open round-trips for any plaintext
//! and context; a single modified byte is always rejected.
#![no_main]
use libfuzzer_sys::fuzz_target;
use vpqc::encryption;
use vpqc_fuzz::{Input, enc_keys};

fuzz_target!(|data: &[u8]| {
    let mut input = Input(data);
    let mode = input.byte();
    let kp = &enc_keys()[(input.byte() % 4) as usize];
    let aad = input.slice();
    let rest = input.rest();
    if mode & 1 == 0 {
        // Hostile ciphertext.
        let _ = encryption::open(&kp.secret, rest, aad);
    } else {
        // Round trip, then tamper with one byte chosen by the input.
        let sealed = encryption::seal(&kp.public, rest, aad).unwrap();
        assert_eq!(encryption::open(&kp.secret, &sealed, aad).unwrap(), rest);
        let i = (mode as usize * 7919 + rest.len()) % sealed.len();
        let mut bad = sealed.clone();
        bad[i] ^= 1 << (mode % 8);
        assert!(encryption::open(&kp.secret, &bad, aad).is_err(), "flip at {i} accepted");
    }
});
