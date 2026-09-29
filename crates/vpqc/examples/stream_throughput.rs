//! In-memory streaming throughput: `cargo run --release -p vpqc --example stream_throughput`.
use std::io::{Read, Write};
use std::time::Instant;

fn main() -> std::io::Result<()> {
    let keys = vpqc::encryption::generate(vpqc::Profile::Standard).expect("keygen");
    let block = vec![0x5au8; 1 << 20];
    let total_mib = 512;

    let t = Instant::now();
    let mut enc = vpqc::stream::Encryptor::new(&keys.public, b"bench", std::io::sink())?;
    for _ in 0..total_mib {
        enc.write_all(&block)?;
    }
    enc.finish()?;
    let e = t.elapsed().as_secs_f64();
    println!("encrypt: {:.0} MiB/s", total_mib as f64 / e);

    let mut ct = Vec::with_capacity((total_mib << 20) + (1 << 20));
    let mut enc = vpqc::stream::Encryptor::new(&keys.public, b"bench", &mut ct)?;
    for _ in 0..total_mib {
        enc.write_all(&block)?;
    }
    enc.finish()?;
    let t = Instant::now();
    let mut dec = vpqc::stream::Decryptor::new(&keys.secret, b"bench", &ct[..])?;
    let mut buf = vec![0u8; 1 << 20];
    let mut n = 0usize;
    loop {
        let r = dec.read(&mut buf)?;
        if r == 0 {
            break;
        }
        n += r;
    }
    assert_eq!(n, total_mib << 20);
    println!(
        "decrypt: {:.0} MiB/s",
        total_mib as f64 / t.elapsed().as_secs_f64()
    );
    Ok(())
}
