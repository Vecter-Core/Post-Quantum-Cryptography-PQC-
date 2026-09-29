//! Secret-independence check under valgrind memcheck (the "ctgrind" technique, Langley 2010).
//!
//! Secret bytes are marked *undefined* with a valgrind client request. Memcheck then reports
//! every conditional branch, and every memory address, computed from them: exactly the two
//! ways code leaks secrets through timing and cache. Unlike timing measurements this has no
//! noise, but it only covers the code paths executed with these inputs, and not
//! variable-latency instructions (such as division on some CPUs).
//!
//! Each case runs in its own process: `vpqc-ct-check --valgrind <case>`, see `grind.sh`.
//! Outside valgrind the client request is a no-op and the cases just run.

use std::hint::black_box;

use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use vpqc_backend_libcrux::{mldsa, mlkem};

/// `VG_USERREQ_TOOL_BASE('M','C')`.
const MC_BASE: u64 = (b'M' as u64) << 24 | (b'C' as u64) << 16;
const MAKE_MEM_UNDEFINED: u64 = MC_BASE + 1;
const MAKE_MEM_DEFINED: u64 = MC_BASE + 2;

#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
fn client_request(request: u64, addr: *const u8, len: usize) {
    let args: [u64; 6] = [request, addr as u64, len as u64, 0, 0, 0];
    // SAFETY: this is valgrind's documented amd64 "special instruction" sequence. The four
    // rotations of rdi total 128 bits and leave it unchanged, and `xchg rbx, rbx` is a no-op, so
    // natively nothing happens. Under valgrind the sequence performs the request described by
    // `args` (a live array for the whole asm block) and writes the result to rdx.
    unsafe {
        core::arch::asm!(
            "rol rdi, 3",
            "rol rdi, 13",
            "rol rdi, 61",
            "rol rdi, 51",
            "xchg rbx, rbx",
            in("rax") args.as_ptr(),
            inout("rdx") 0u64 => _,
            inout("rdi") 0u64 => _,
        );
    }
}

#[cfg(not(target_arch = "x86_64"))]
fn client_request(_: u64, _: *const u8, _: usize) {
    eprintln!("the valgrind mode supports x86_64 only");
    std::process::exit(3);
}

/// Mark `bytes` as secret: memcheck reports any branch or address that depends on them.
fn secret(bytes: &[u8]) {
    client_request(MAKE_MEM_UNDEFINED, bytes.as_ptr(), bytes.len());
}

/// Declassify an output (a ciphertext, signature or shared secret handed to the caller) so
/// the harness itself does not trigger reports.
fn public(bytes: &[u8]) {
    client_request(MAKE_MEM_DEFINED, bytes.as_ptr(), bytes.len());
}

fn fixed<const N: usize>(b: u8) -> [u8; N] {
    std::array::from_fn(|i| b.wrapping_add(i as u8).wrapping_mul(29))
}

/// Case names, in the order `grind.sh` runs them.
pub const CASES: &[&str] = &[
    "control-leaky-compare",
    "mlkem768-decaps-valid",
    "mlkem768-decaps-invalid",
    "mlkem1024-decaps",
    "xwing-decaps",
    "mlkem1024-p384-decaps",
    "x25519",
    "chacha20poly1305-seal",
    "ed25519-sign",
    "ecdsa-p384-sign",
    "mldsa65-sign",
];

fn mlkem_decaps(level: mlkem::Level, corrupt: bool) {
    let kp = mlkem::keygen(level, &fixed::<64>(1));
    let (mut ct, _) = mlkem::encapsulate(level, &kp.public, &fixed::<32>(2)).expect("encaps");
    if corrupt {
        ct[5] ^= 0x10;
    }
    // Layout `s || ek || H(ek) || z`: s and z are secret; ek and H(ek) are public.
    let dk = kp.decapsulation_key.to_vec();
    let s_len = dk.len() - kp.public.len() - 64;
    secret(&dk[..s_len]);
    secret(&dk[dk.len() - 32..]);
    let ss = mlkem::decapsulate(level, &dk, &ct).expect("decaps");
    public(&*ss);
    black_box(&*ss);
}

/// Run one case. Returns false for an unknown name.
pub fn run(case: &str) -> bool {
    match case {
        "control-leaky-compare" => {
            // Must be reported: branches on secret bytes.
            let key: [u8; 32] = fixed(13);
            secret(&key);
            black_box(crate::leaky_eq(black_box(&key), &fixed::<32>(14)));
        }
        "mlkem768-decaps-valid" => mlkem_decaps(mlkem::Level::L768, false),
        "mlkem768-decaps-invalid" => mlkem_decaps(mlkem::Level::L768, true),
        "mlkem1024-decaps" => mlkem_decaps(mlkem::Level::L1024, false),
        "xwing-decaps" => {
            let sk: [u8; 32] = fixed(3);
            let pk = vpqc_hybrid::xwing::public_key_from_secret(&sk);
            let (ct, _) =
                vpqc_hybrid::xwing::encapsulate_derand(&pk, &fixed::<64>(4)).expect("encaps");
            secret(&sk);
            let ss = vpqc_hybrid::xwing::decapsulate_raw(&sk, &ct).expect("decaps");
            public(&*ss);
            black_box(&*ss);
        }
        "mlkem1024-p384-decaps" => {
            use vpqc_hybrid::mlkem1024_p384 as kem;
            let sk: [u8; 32] = fixed(15);
            let pk = kem::public_key_from_secret(&sk).expect("pk");
            let (ct, _) = kem::encapsulate_derand(&pk, &fixed::<80>(16)).expect("encaps");
            secret(&sk);
            let ss = kem::decapsulate_raw(&sk, &ct).expect("decaps");
            public(&*ss);
            black_box(&*ss);
        }
        "x25519" => {
            let sk: [u8; 32] = fixed(5);
            secret(&sk);
            let out = x25519_dalek::x25519(sk, x25519_dalek::X25519_BASEPOINT_BYTES);
            public(&out);
            black_box(out);
        }
        "chacha20poly1305-seal" => {
            let key: [u8; 32] = fixed(6);
            let mut buf = vec![7u8; 1000];
            secret(&key);
            secret(&buf);
            let cipher = ChaCha20Poly1305::new_from_slice(&key).expect("key");
            let tag = cipher
                .encrypt_inout_detached(
                    &Nonce::from(fixed::<12>(8)),
                    b"aad",
                    buf.as_mut_slice().into(),
                )
                .expect("seal");
            public(&buf);
            public(&tag);
            black_box((&buf, tag));
        }
        "ed25519-sign" => {
            use ed25519_dalek::{Signer, SigningKey};
            let seed: [u8; 32] = fixed(9);
            secret(&seed);
            let sig = SigningKey::from_bytes(&seed).sign(b"message").to_bytes();
            public(&sig);
            black_box(sig);
        }
        "ecdsa-p384-sign" => {
            use p384::ecdsa::signature::Signer;
            use p384::ecdsa::{Signature, SigningKey};
            let scalar: [u8; 48] = fixed(10);
            secret(&scalar);
            let sk = p384::SecretKey::from_slice(&scalar).expect("scalar");
            let sig: Signature = SigningKey::from(&sk).sign(b"message");
            let bytes = sig.to_bytes();
            public(&bytes);
            black_box(bytes);
        }
        "mldsa65-sign" => {
            let (_, sk) = mldsa::keygen(mldsa::Level::L65, &fixed::<32>(11));
            // Layout `rho || K || tr || s1 || s2 || t0`: rho and tr are public.
            secret(&sk[32..64]);
            secret(&sk[128..]);
            let sig = mldsa::sign(mldsa::Level::L65, &sk, b"message", b"ctx", &fixed::<32>(12))
                .expect("sign");
            public(&sig);
            black_box(&sig);
        }
        _ => return false,
    }
    true
}
