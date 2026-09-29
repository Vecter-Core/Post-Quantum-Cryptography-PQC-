//! Streaming (ADR-0007).
//! * Differential: `Decryptor` (pull) and `PushDecryptor` (push, input-chosen split sizes)
//!   must agree on every input: both fail, or both return the same plaintext.
//! * Round trip with input-chosen chunk size and write pattern; any byte flip is rejected.
#![no_main]
use std::io::{Read, Write};

use libfuzzer_sys::fuzz_target;
use vpqc::stream::{Decryptor, Encryptor, PushDecryptor, StreamOptions};
use vpqc_fuzz::{Input, enc_keys};

fn pull(sk: &vpqc::SecretKey, aad: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
    let mut d = Decryptor::new(sk, aad, ct).ok()?;
    let mut out = Vec::new();
    d.read_to_end(&mut out).ok()?;
    Some(out)
}

fn push(sk: &vpqc::SecretKey, aad: &[u8], ct: &[u8], step: usize) -> Option<Vec<u8>> {
    let mut d = PushDecryptor::new(sk, aad);
    let mut out = Vec::new();
    for piece in ct.chunks(step.max(1)) {
        out.extend(d.update(piece).ok()?);
    }
    out.extend(d.finish().ok()?);
    Some(out)
}

fuzz_target!(|data: &[u8]| {
    let mut input = Input(data);
    let mode = input.byte();
    let kp = &enc_keys()[(input.byte() % 4) as usize];
    let step = input.byte() as usize * 13 + 1;
    let aad = input.slice();
    let rest = input.rest();
    if mode & 1 == 0 {
        let a = pull(&kp.secret, aad, rest);
        let b = push(&kp.secret, aad, rest, step);
        assert_eq!(a, b, "pull and push decryptors disagree");
    } else {
        let chunk_log = 10 + (mode >> 1) % 3; // 1..4 KiB chunks reach multi-chunk states quickly
        let mut e = Encryptor::with_options(&kp.public, aad, Vec::new(), StreamOptions { chunk_log }).unwrap();
        for piece in rest.chunks(step) {
            e.write_all(piece).unwrap();
        }
        let ct = e.finish().unwrap();
        assert_eq!(pull(&kp.secret, aad, &ct).as_deref(), Some(rest));
        assert_eq!(push(&kp.secret, aad, &ct, step).as_deref(), Some(rest));
        let i = (step * 104729 + rest.len()) % ct.len();
        let mut bad = ct.clone();
        bad[i] ^= 0x80;
        assert_eq!(pull(&kp.secret, aad, &bad), None, "flip at {i} accepted");
        assert_eq!(push(&kp.secret, aad, &bad, step), None, "flip at {i} accepted (push)");
        let cut = &ct[..(step * 7) % ct.len()];
        assert_eq!(pull(&kp.secret, aad, cut), None, "truncation accepted");
    }
});
