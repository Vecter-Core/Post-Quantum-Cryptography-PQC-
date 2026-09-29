//! dudect-style timing leakage check (Reparaz, Balasch, Verbauwhede, "Dude, is my code constant
//! time?", 2017).
//!
//! For each operation, inputs of two classes are measured in random interleaved order; a
//! Welch t-test compares the timing distributions (after cropping outliers at several
//! percentiles). `|t| > 4.5` indicates a timing difference that depends on the class.
//!
//! Deliberately leaky **controls** run alongside: if the harness does not flag them, the machine
//! is too noisy and every "no leak" result is meaningless, so the tool fails. Results are
//! evidence, not proof: a pass means no leak was detected with this many samples on this machine
//! and compiler.
//!
//! ```text
//! cargo run --release -p vpqc-ct-check -- [samples]                  gating checks
//! cargo run --release -p vpqc-ct-check -- --fixed-inputs [samples]   informational, see README
//! tools/ct-check/grind.sh                                            valgrind secret tracking
//! ```

mod grind;

use std::hint::black_box;
use std::time::Instant;

use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce, Tag};
use vpqc_backend_libcrux::mlkem::{self, Level};

const THRESHOLD: f64 = 4.5;
/// Distinct inputs per class in the pooled tests.
const POOL: usize = 512;
/// ML-KEM-768 decapsulation key layout (FIPS 203): `s || ek || H(ek) || z`.
const DK768_S: usize = 1152;
const DK768_EK_END: usize = DK768_S + 1184 + 32;

fn rand<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).expect("rng");
    b
}

/// Welch's t statistic between two samples.
fn welch(a: &[f64], b: &[f64]) -> f64 {
    let mean = |v: &[f64]| v.iter().sum::<f64>() / v.len() as f64;
    let var =
        |v: &[f64], m: f64| v.iter().map(|x| (x - m).powi(2)).sum::<f64>() / (v.len() - 1) as f64;
    let (ma, mb) = (mean(a), mean(b));
    let (va, vb) = (var(a, ma), var(b, mb));
    (ma - mb) / (va / a.len() as f64 + vb / b.len() as f64).sqrt()
}

/// Largest |t| over several cropping percentiles (dudect's approach to heavy-tailed noise).
fn max_t(samples: &[(u8, f64)]) -> f64 {
    let mut all: Vec<f64> = samples.iter().map(|s| s.1).collect();
    all.sort_by(|a, b| a.partial_cmp(b).expect("no NaN"));
    let mut worst: f64 = 0.0;
    for pct in [0.5, 0.7, 0.9, 0.99, 1.0] {
        let cut = all[((all.len() - 1) as f64 * pct) as usize];
        let class = |c: u8| {
            samples
                .iter()
                .filter(|s| s.0 == c && s.1 <= cut)
                .map(|s| s.1)
                .collect::<Vec<_>>()
        };
        let (a, b) = (class(0), class(1));
        if a.len() > 10 && b.len() > 10 {
            worst = worst.max(welch(&a, &b).abs());
        }
    }
    worst
}

/// Measure `op(class, i)` for `n` random class choices; `batch` calls per measurement reduce
/// timer quantisation for fast operations. `i` lets pooled tests pick a different input each
/// time.
fn measure(n: usize, batch: usize, mut op: impl FnMut(u8, usize)) -> f64 {
    let classes: Vec<u8> = (0..n).map(|_| rand::<1>()[0] & 1).collect();
    for (i, &c) in classes.iter().take(n / 20).enumerate() {
        op(c, i); // warm-up
    }
    let mut samples = Vec::with_capacity(n);
    for (i, &c) in classes.iter().enumerate() {
        let t = Instant::now();
        for _ in 0..batch {
            op(c, i);
        }
        samples.push((c, t.elapsed().as_nanos() as f64));
    }
    max_t(&samples)
}

fn report(name: &str, t: f64, expect_leak: bool) -> bool {
    let leak = t > THRESHOLD;
    let verdict = match (leak, expect_leak) {
        (true, true) => "LEAK DETECTED (expected: control)",
        (false, true) => "NOT DETECTED: harness too insensitive",
        (true, false) => "POSSIBLE LEAK",
        (false, false) => "no leak detected",
    };
    println!("{name:<62} max|t| = {t:>8.2}  {verdict}");
    leak == expect_leak
}

/// Early-exit comparison: the control that must be flagged.
#[inline(never)]
fn leaky_eq(a: &[u8], b: &[u8]) -> bool {
    for (x, y) in a.iter().zip(b) {
        if x != y {
            return false;
        }
    }
    true
}

/// Flip one random bit within the first `limit` bytes.
fn corrupt(ct: &mut [u8], limit: usize) {
    let r = rand::<3>();
    let i = u16::from_le_bytes([r[0], r[1]]) as usize % limit;
    ct[i] ^= 1 << (r[2] & 7);
}

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--valgrind") {
        match args.get(1).map(String::as_str) {
            Some("list") => grind::CASES.iter().for_each(|c| println!("{c}")),
            Some(case) if grind::run(case) => {}
            _ => {
                eprintln!("usage: vpqc-ct-check --valgrind <list | case>");
                std::process::exit(3);
            }
        }
        return;
    }
    let fixed = args.iter().any(|a| a == "--fixed-inputs");
    args.retain(|a| a != "--fixed-inputs");
    let n: usize = args.first().and_then(|s| s.parse().ok()).unwrap_or(200_000);
    println!(
        "dudect-style timing check, {n} measurements per operation, threshold |t| > {THRESHOLD}\n"
    );

    // Control: differ in the first byte vs in the last byte.
    let x = vec![7u8; 1024];
    let mut early = x.clone();
    early[0] ^= 1;
    let mut late = x.clone();
    late[1023] ^= 1;
    let mut ok = report(
        "control: early-exit compare (first vs last byte differs)",
        measure(n, 1, |c, _| {
            black_box(leaky_eq(
                black_box(&x),
                black_box(if c == 0 { &early } else { &late }),
            ));
        }),
        true,
    );
    if !ok {
        println!("\nThe control leak was not detected; results below would be meaningless.");
        std::process::exit(2);
    }
    if fixed {
        fixed_inputs(n);
        return;
    }

    // ML-KEM-768 decapsulation: many valid vs many corrupted ciphertexts, each copied into the
    // same buffer. FIPS 203 implicit rejection must not reveal by timing whether a ciphertext
    // was valid (the property chosen-ciphertext attacks exploit).
    let kp = mlkem::keygen(Level::L768, &rand::<64>());
    let pool = |bad: bool| -> Vec<Vec<u8>> {
        (0..POOL)
            .map(|_| {
                let (mut ct, _) =
                    mlkem::encapsulate(Level::L768, &kp.public, &rand::<32>()).expect("encaps");
                if bad {
                    let len = ct.len();
                    corrupt(&mut ct, len);
                }
                ct
            })
            .collect()
    };
    let (valid, invalid) = (pool(false), pool(true));
    let mut w = valid[0].clone();
    ok &= report(
        "ML-KEM-768 decaps: valid vs corrupted ciphertexts (pools)",
        measure(n / 10, 1, |c, i| {
            w.copy_from_slice(if c == 0 {
                &valid[i % POOL]
            } else {
                &invalid[i % POOL]
            });
            black_box(mlkem::decapsulate(Level::L768, &kp.decapsulation_key, black_box(&w)).ok());
        }),
        false,
    );

    // Control at realistic scale: the same decapsulation followed by an early-exit comparison
    // of the re-encrypted ciphertext (the classic Fujisaki-Okamoto implementation mistake):
    // equal for valid ciphertexts, different from the first byte for corrupted ones. This shows
    // the harness sees a leak of that size underneath the cost and noise of decapsulation.
    let mut first_differs = valid[0].clone();
    first_differs[0] ^= 1;
    ok &= report(
        "control: ML-KEM-768 decaps + early-exit re-encryption compare",
        measure(n / 10, 1, |c, i| {
            w.copy_from_slice(if c == 0 {
                &valid[i % POOL]
            } else {
                &invalid[i % POOL]
            });
            black_box(mlkem::decapsulate(Level::L768, &kp.decapsulation_key, black_box(&w)).ok());
            let re = if c == 0 { &valid[0] } else { &first_differs };
            black_box(leaky_eq(black_box(&valid[0]), black_box(re)));
        }),
        true,
    );

    // X-Wing decapsulation (the hybrid vpqc uses by default): same construction, corrupting
    // the ML-KEM part (the first 1088 bytes).
    let sk: [u8; 32] = rand();
    let pk = vpqc_hybrid::xwing::public_key_from_secret(&sk);
    let xpool = |bad: bool| -> Vec<Vec<u8>> {
        (0..POOL)
            .map(|_| {
                let (mut ct, _) =
                    vpqc_hybrid::xwing::encapsulate_derand(&pk, &rand::<64>()).expect("encaps");
                if bad {
                    corrupt(&mut ct, 1088);
                }
                ct
            })
            .collect()
    };
    let (xvalid, xinvalid) = (xpool(false), xpool(true));
    let mut xw = xvalid[0].clone();
    ok &= report(
        "X-Wing decaps: valid vs corrupted ciphertexts (pools)",
        measure(n / 10, 1, |c, i| {
            xw.copy_from_slice(if c == 0 {
                &xvalid[i % POOL]
            } else {
                &xinvalid[i % POOL]
            });
            black_box(vpqc_hybrid::xwing::decapsulate_raw(&sk, black_box(&xw)).ok());
        }),
        false,
    );

    // X25519 scalar multiplication: two different secret scalars.
    let (s0, s1): ([u8; 32], [u8; 32]) = (rand(), [0x01; 32]);
    let point = x25519_dalek::X25519_BASEPOINT_BYTES;
    ok &= report(
        "X25519: random scalar vs low-weight scalar",
        measure(n / 4, 1, |c, _| {
            black_box(x25519_dalek::x25519(
                black_box(if c == 0 { s0 } else { s1 }),
                point,
            ));
        }),
        false,
    );

    // Control at tag scale: a 16-byte early-exit comparison is only a few nanoseconds.
    let (tag_ref, mut tag_first, mut tag_last) = ([9u8; 16], [9u8; 16], [9u8; 16]);
    tag_first[0] ^= 1;
    tag_last[15] ^= 1;
    ok &= report(
        "control: 16-byte early-exit tag compare",
        measure(n, 8, |c, _| {
            black_box(leaky_eq(
                black_box(&tag_ref),
                black_box(if c == 0 { &tag_first } else { &tag_last }),
            ));
        }),
        true,
    );

    // ChaCha20-Poly1305 tag check: tag wrong in its first byte vs its last byte. An early-exit
    // tag comparison would show here.
    let cipher = ChaCha20Poly1305::new_from_slice(&rand::<32>()).expect("key");
    let nonce = Nonce::from(rand::<12>());
    let mut buf = vec![0u8; 64];
    let tag = cipher
        .encrypt_inout_detached(&nonce, b"", buf.as_mut_slice().into())
        .expect("encrypt");
    let (mut t_first, mut t_last) = (tag, tag);
    t_first[0] ^= 1;
    t_last[15] ^= 1;
    let ct64 = buf.clone();
    ok &= report(
        "ChaCha20-Poly1305 open: tag wrong at first vs last byte",
        measure(n, 8, |c, _| {
            let mut b = ct64.clone();
            let t: &Tag = if c == 0 { &t_first } else { &t_last };
            black_box(
                cipher
                    .decrypt_inout_detached(&nonce, b"", b.as_mut_slice().into(), t)
                    .is_err(),
            );
        }),
        false,
    );

    println!();
    if ok {
        println!("All checks as expected.");
    } else {
        println!("Unexpected result: see above.");
        std::process::exit(1);
    }
}

/// Informational fixed-input tests (never fail the run). Each pair compares two *specific*
/// inputs, copied into the same buffer, so the result is sensitive to any data-dependent timing,
/// including dependence on public data. See README for how to read them.
fn fixed_inputs(n: usize) {
    let run = |name: String, mut op: Box<dyn FnMut(u8)>| {
        let t = measure(n / 10, 1, |c, _| op(c));
        println!("{name:<62} max|t| = {t:>8.2}");
    };
    println!("\nInformational fixed-input comparisons (4 random pairs each):");
    for pair in 0..4 {
        let kp = mlkem::keygen(Level::L768, &rand::<64>());
        let (a, _) = mlkem::encapsulate(Level::L768, &kp.public, &rand::<32>()).expect("encaps");
        let (b, _) = mlkem::encapsulate(Level::L768, &kp.public, &rand::<32>()).expect("encaps");
        let mut w = a.clone();
        run(
            format!("ML-KEM-768 decaps, valid ct A vs valid ct B, pair {pair}"),
            Box::new(move |c| {
                w.copy_from_slice(if c == 0 { &a } else { &b });
                black_box(
                    mlkem::decapsulate(Level::L768, &kp.decapsulation_key, black_box(&w)).ok(),
                );
            }),
        );
    }
    for pair in 0..4 {
        // Same ciphertext and same public part of the key; only the secret s and z differ.
        let k1 = mlkem::keygen(Level::L768, &rand::<64>());
        let k2 = mlkem::keygen(Level::L768, &rand::<64>());
        let (ct, _) = mlkem::encapsulate(Level::L768, &k1.public, &rand::<32>()).expect("encaps");
        let mut mixed = k2.decapsulation_key.to_vec();
        mixed[DK768_S..DK768_EK_END].copy_from_slice(&k1.decapsulation_key[DK768_S..DK768_EK_END]);
        let first = k1.decapsulation_key.to_vec();
        let mut kw = first.clone();
        run(
            format!("ML-KEM-768 decaps, same ct and ek, secret s differs, pair {pair}"),
            Box::new(move |c| {
                kw.copy_from_slice(if c == 0 { &first } else { &mixed });
                black_box(mlkem::decapsulate(Level::L768, black_box(&kw), &ct).ok());
            }),
        );
    }
    for pair in 0..4 {
        // Reference: ARX-only, constant time by construction.
        let (ka, kb) = (rand::<32>(), rand::<32>());
        let mut kw = ka;
        let nonce = Nonce::from([0u8; 12]);
        let mut buf = vec![0u8; 16384];
        run(
            format!("reference: ChaCha20-Poly1305 16 KiB, key A vs key B, pair {pair}"),
            Box::new(move |c| {
                kw.copy_from_slice(if c == 0 { &ka } else { &kb });
                let cipher = ChaCha20Poly1305::new_from_slice(black_box(&kw)).expect("key");
                black_box(
                    cipher
                        .encrypt_inout_detached(&nonce, b"", buf.as_mut_slice().into())
                        .ok(),
                );
            }),
        );
    }
}
