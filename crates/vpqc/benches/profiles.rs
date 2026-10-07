#![allow(missing_docs)] // criterion_group! generates an undocumented function
//! Latency of the main operations for every profile, and the sizes they produce.
//!
//! `cargo bench -p vpqc` runs the timing benchmarks (criterion); the size table is printed first.
//! Numbers depend on the machine; docs/PERFORMANCE.md records one run with its hardware.

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use vpqc::{Profile, encryption, keys, signing};

fn sizes() {
    println!(
        "\n{:<10} {:>10} {:>10} {:>12} | {:>10} {:>10} {:>10}",
        "profile", "enc pk", "enc sk", "seal(0 B)", "sig pk", "sig sk", "signature"
    );
    for p in Profile::ALL {
        let e = encryption::generate(p).unwrap();
        let s = signing::generate(p).unwrap();
        let sealed = encryption::seal(&e.public, b"", b"").unwrap();
        let sig = signing::sign(&s.secret, b"", b"bench").unwrap();
        println!(
            "{:<10} {:>10} {:>10} {:>12} | {:>10} {:>10} {:>10}",
            p.name(),
            keys::public_to_bytes(&e.public).len(),
            keys::secret_to_bytes(&e.secret).len(),
            sealed.len(),
            keys::public_to_bytes(&s.public).len(),
            keys::secret_to_bytes(&s.secret).len(),
            sig.len()
        );
    }
    println!();
}

fn bench(c: &mut Criterion) {
    sizes();
    let msg = vec![0xa5u8; 1024];
    for p in Profile::ALL {
        let name = p.name();
        let mut g = c.benchmark_group(format!("encryption/{name}"));
        g.bench_function("keygen", |b| {
            b.iter(|| black_box(encryption::generate(p).unwrap()))
        });
        let k = encryption::generate(p).unwrap();
        g.throughput(Throughput::Bytes(msg.len() as u64));
        g.bench_function("seal 1 KiB", |b| {
            b.iter(|| black_box(encryption::seal(&k.public, black_box(&msg), b"ctx").unwrap()))
        });
        let sealed = encryption::seal(&k.public, &msg, b"ctx").unwrap();
        g.bench_function("open 1 KiB", |b| {
            b.iter(|| black_box(encryption::open(&k.secret, black_box(&sealed), b"ctx").unwrap()))
        });
        g.finish();

        let mut g = c.benchmark_group(format!("signing/{name}"));
        g.bench_function("keygen", |b| {
            b.iter(|| black_box(signing::generate(p).unwrap()))
        });
        let k = signing::generate(p).unwrap();
        g.bench_function("sign 1 KiB", |b| {
            b.iter(|| black_box(signing::sign(&k.secret, black_box(&msg), b"bench").unwrap()))
        });
        let sig = signing::sign(&k.secret, &msg, b"bench").unwrap();
        g.bench_function("verify 1 KiB", |b| {
            b.iter(|| {
                signing::verify(&k.public, black_box(&msg), b"bench", black_box(&sig)).unwrap()
            })
        });
        g.finish();
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
