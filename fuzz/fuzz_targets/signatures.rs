//! Signatures: verification never panics or accepts garbage; sign/verify round-trips for any
//! message and context (<= 255 bytes); a modified signature, message or context is rejected.
#![no_main]
use libfuzzer_sys::fuzz_target;
use vpqc::signing;
use vpqc_fuzz::{Input, sig_keys};

fuzz_target!(|data: &[u8]| {
    let mut input = Input(data);
    let mode = input.byte();
    let kp = &sig_keys()[(input.byte() % 4) as usize];
    let ctx = input.slice();
    let rest = input.rest();
    if mode & 1 == 0 {
        // Treat the remaining input as a signature over a fixed message.
        let _ = signing::verify(&kp.public, b"fixed message", ctx, rest);
    } else {
        let sig = signing::sign(&kp.secret, rest, ctx).unwrap();
        signing::verify(&kp.public, rest, ctx, &sig).unwrap();
        let i = (mode as usize * 31 + rest.len()) % sig.len();
        let mut bad = sig.clone();
        bad[i] ^= 1 << (mode % 8);
        assert!(signing::verify(&kp.public, rest, ctx, &bad).is_err(), "modified signature accepted");
        let mut msg = rest.to_vec();
        msg.push(mode);
        assert!(signing::verify(&kp.public, &msg, ctx, &sig).is_err(), "other message accepted");
        if ctx.len() < 255 {
            let mut c = ctx.to_vec();
            c.push(0);
            assert!(signing::verify(&kp.public, rest, &c, &sig).is_err(), "other context accepted");
        }
    }
});
