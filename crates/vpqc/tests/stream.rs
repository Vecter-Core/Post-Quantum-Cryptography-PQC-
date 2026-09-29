//! Streaming encryption (ADR-0007): boundaries, tampering, truncation, reordering, files.

use std::io::{Read, Write};

use vpqc::stream::{self, Decryptor, Encryptor, StreamOptions};
use vpqc::{Error, Profile, encryption, signing};
use vpqc_core::testing::FixedRandom;

const SMALL: StreamOptions = StreamOptions { chunk_log: 10 }; // 1 KiB chunks
const CHUNK: usize = 1024;

fn data(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 31 % 251) as u8).collect()
}

fn encrypt(pk: &vpqc::PublicKey, aad: &[u8], pt: &[u8], opts: StreamOptions) -> Vec<u8> {
    let mut e = Encryptor::with_options(pk, aad, Vec::new(), opts).unwrap();
    e.write_all(pt).unwrap();
    e.finish().unwrap()
}

fn decrypt(sk: &vpqc::SecretKey, aad: &[u8], ct: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut d = Decryptor::new(sk, aad, ct)?;
    let mut out = Vec::new();
    d.read_to_end(&mut out)?;
    Ok(out)
}

fn header_len(ct_len_of_kem: usize) -> usize {
    12 + ct_len_of_kem
}

#[test]
fn round_trip_chunk_boundaries_all_profiles() {
    for profile in Profile::ALL {
        let kp = encryption::generate(profile).unwrap();
        let kem_ct = vpqc::kem(profile.kem()).unwrap().ciphertext_len();
        for n in [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 2 * CHUNK, 5000] {
            let pt = data(n);
            let ct = encrypt(&kp.public, b"ctx", &pt, SMALL);
            let chunks = n.div_ceil(CHUNK).max(1);
            assert_eq!(
                ct.len(),
                header_len(kem_ct) + n + 16 * chunks,
                "{profile:?} n={n}"
            );
            assert_eq!(
                decrypt(&kp.secret, b"ctx", &ct).unwrap(),
                pt,
                "{profile:?} n={n}"
            );
        }
    }
}

#[test]
fn write_pattern_does_not_change_output_semantics() {
    let kp = encryption::generate(Profile::Standard).unwrap();
    let pt = data(4 * CHUNK + 7);
    let mut e = Encryptor::with_options(&kp.public, b"", Vec::new(), SMALL).unwrap();
    for b in &pt {
        e.write_all(std::slice::from_ref(b)).unwrap(); // one byte at a time
    }
    let ct = e.finish().unwrap();
    assert_eq!(decrypt(&kp.secret, b"", &ct).unwrap(), pt);
    // Reading with a tiny buffer also works.
    let mut d = Decryptor::new(&kp.secret, b"", &ct[..]).unwrap();
    let mut out = Vec::new();
    let mut b = [0u8; 3];
    loop {
        let n = d.read(&mut b).unwrap();
        if n == 0 {
            break;
        }
        out.extend_from_slice(&b[..n]);
    }
    assert_eq!(out, pt);
}

#[test]
fn every_byte_flip_is_rejected() {
    let kp = encryption::generate(Profile::Standard).unwrap();
    let ct = encrypt(&kp.public, b"a", &data(2 * CHUNK + 100), SMALL);
    for i in 0..ct.len() {
        let mut bad = ct.clone();
        bad[i] ^= 0x01;
        assert!(
            decrypt(&kp.secret, b"a", &bad).is_err(),
            "flip at {i} accepted"
        );
    }
}

#[test]
fn every_truncation_and_extension_is_rejected() {
    let kp = encryption::generate(Profile::Standard).unwrap();
    for n in [0, 10, CHUNK, 3 * CHUNK] {
        let ct = encrypt(&kp.public, b"", &data(n), SMALL);
        for len in 0..ct.len() {
            assert!(
                decrypt(&kp.secret, b"", &ct[..len]).is_err(),
                "n={n} truncated to {len}"
            );
        }
        let mut longer = ct.clone();
        longer.push(0);
        assert!(decrypt(&kp.secret, b"", &longer).is_err(), "n={n} extended");
    }
}

#[test]
fn chunk_reordering_and_splicing_are_rejected() {
    let kp = encryption::generate(Profile::Standard).unwrap();
    let h = header_len(1120);
    let ct = encrypt(&kp.public, b"", &data(3 * CHUNK + 1), SMALL);
    let c = CHUNK + 16;
    // Swap chunks 0 and 1.
    let mut swapped = ct[..h].to_vec();
    swapped.extend_from_slice(&ct[h + c..h + 2 * c]);
    swapped.extend_from_slice(&ct[h..h + c]);
    swapped.extend_from_slice(&ct[h + 2 * c..]);
    assert!(decrypt(&kp.secret, b"", &swapped).is_err());
    // Drop a middle chunk.
    let mut dropped = ct[..h + c].to_vec();
    dropped.extend_from_slice(&ct[h + 2 * c..]);
    assert!(decrypt(&kp.secret, b"", &dropped).is_err());
    // Splice a chunk from another stream to the same key: different key, rejected.
    let other = encrypt(&kp.public, b"", &data(3 * CHUNK + 1), SMALL);
    let mut spliced = ct[..h + c].to_vec();
    spliced.extend_from_slice(&other[h + c..]);
    assert!(decrypt(&kp.secret, b"", &spliced).is_err());
}

#[test]
fn full_final_chunk_cannot_be_reinterpreted() {
    // Exactly 2 chunks: the second is full and final. Removing it leaves a full non-final
    // first chunk at end of input, which must fail (it was encrypted with last = 0).
    let kp = encryption::generate(Profile::Standard).unwrap();
    let h = header_len(1120);
    let ct = encrypt(&kp.public, b"", &data(2 * CHUNK), SMALL);
    assert_eq!(ct.len(), h + 2 * (CHUNK + 16));
    assert!(decrypt(&kp.secret, b"", &ct[..h + CHUNK + 16]).is_err());
}

#[test]
fn empty_final_chunk_after_data_is_rejected() {
    // One encoding per plaintext: a trailing empty final chunk is only valid for empty input.
    let kp = encryption::generate(Profile::Standard).unwrap();
    for n in [1, CHUNK, 2 * CHUNK + 3] {
        let mut e = Encryptor::with_options(&kp.public, b"", Vec::new(), SMALL).unwrap();
        e.write_all(&data(n)).unwrap();
        let ct = e.finish_noncanonical_for_testing().unwrap();
        assert!(decrypt(&kp.secret, b"", &ct).is_err(), "n={n}");
    }
    let e = Encryptor::with_options(&kp.public, b"", Vec::new(), SMALL).unwrap();
    let ct = e.finish_noncanonical_for_testing().unwrap();
    assert_eq!(
        decrypt(&kp.secret, b"", &ct).unwrap(),
        b"",
        "empty plaintext is canonical"
    );
}

#[test]
fn context_key_and_header_binding() {
    let kp = encryption::generate(Profile::Standard).unwrap();
    let other = encryption::generate(Profile::Standard).unwrap();
    let ct = encrypt(&kp.public, b"backup/2026-09-29", &data(3000), SMALL);
    assert!(
        decrypt(&kp.secret, b"backup/2026-09-30", &ct).is_err(),
        "aad"
    );
    assert!(
        decrypt(&other.secret, b"backup/2026-09-29", &ct).is_err(),
        "key"
    );
    // Change the chunk size in the header to another valid value.
    let mut hdr = ct.clone();
    hdr[9] = 11;
    assert!(
        decrypt(&kp.secret, b"backup/2026-09-29", &hdr).is_err(),
        "chunk_log"
    );
    // Out-of-range chunk size is refused before any allocation.
    hdr[9] = 30;
    let e = decrypt(&kp.secret, b"backup/2026-09-29", &hdr).unwrap_err();
    assert!(matches!(stream::crypto_error(&e), Some(Error::Format(_))));
}

#[test]
fn wrong_key_kinds_and_formats() {
    let enc = encryption::generate(Profile::Standard).unwrap();
    let cnsa = encryption::generate(Profile::Cnsa2).unwrap();
    let sig = signing::generate(Profile::Standard).unwrap();
    let ct = encrypt(&enc.public, b"", b"hello", SMALL);
    let e = decrypt(&cnsa.secret, b"", &ct).unwrap_err();
    assert_eq!(stream::crypto_error(&e), Some(&Error::AlgorithmMismatch));
    assert!(Encryptor::new(&sig.public, b"", Vec::new()).is_err());
    // A stream is not a sealed box and vice versa.
    assert!(encryption::open(&enc.secret, &ct, b"").is_err());
    let sealed = encryption::seal(&enc.public, b"hello", b"").unwrap();
    assert!(decrypt(&enc.secret, b"", &sealed).is_err());
}

#[test]
fn unfinished_stream_is_rejected() {
    let kp = encryption::generate(Profile::Standard).unwrap();
    let mut buf = Vec::new();
    {
        let mut e = Encryptor::with_options(&kp.public, b"", &mut buf, SMALL).unwrap();
        e.write_all(&data(5000)).unwrap();
        // dropped without finish()
    }
    assert!(decrypt(&kp.secret, b"", &buf).is_err());
}

#[test]
fn failure_is_sticky_and_errors_are_classified() {
    let kp = encryption::generate(Profile::Standard).unwrap();
    let mut ct = encrypt(&kp.public, b"", &data(3 * CHUNK), SMALL);
    let last = ct.len() - 1;
    ct[last] ^= 1;
    let mut d = Decryptor::new(&kp.secret, b"", &ct[..]).unwrap();
    let mut out = Vec::new();
    let e = d.read_to_end(&mut out).unwrap_err();
    assert_eq!(stream::crypto_error(&e), Some(&Error::DecryptionFailed));
    assert!(d.read(&mut [0u8; 10]).is_err(), "decryptor stays failed");
    // Plain I/O errors are not crypto errors.
    let io = std::io::Error::other("disk");
    assert_eq!(stream::crypto_error(&io), None);
}

#[test]
fn default_chunk_size_large_data() {
    let kp = encryption::generate(Profile::High).unwrap();
    let pt: Vec<u8> = (0..3_000_000u32).map(|i| (i ^ (i >> 7)) as u8).collect();
    let mut ct = Vec::new();
    stream::seal_stream(&kp.public, b"x", &pt[..], &mut ct).unwrap();
    let mut back = Vec::new();
    assert_eq!(
        stream::open_stream(&kp.secret, b"x", &ct[..], &mut back).unwrap(),
        pt.len() as u64
    );
    assert_eq!(back, pt);
}

#[test]
fn file_api_is_atomic() {
    let dir = tempfile::tempdir().unwrap();
    let kp = encryption::generate(Profile::Standard).unwrap();
    let plain = dir.path().join("disk.img");
    let enc = dir.path().join("disk.img.vpqc");
    let out = dir.path().join("restored.img");
    let pt = data(200_000);
    std::fs::write(&plain, &pt).unwrap();
    assert_eq!(
        stream::encrypt_file(&kp.public, b"img", &plain, &enc).unwrap(),
        pt.len() as u64
    );
    assert_eq!(
        stream::decrypt_file(&kp.secret, b"img", &enc, &out).unwrap(),
        pt.len() as u64
    );
    assert_eq!(std::fs::read(&out).unwrap(), pt);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&out).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    // Truncated ciphertext: no output file, no temporary file left behind.
    let bad = dir.path().join("bad.vpqc");
    let ct = std::fs::read(&enc).unwrap();
    std::fs::write(&bad, &ct[..ct.len() - 100]).unwrap();
    let target = dir.path().join("should-not-exist.img");
    assert!(stream::decrypt_file(&kp.secret, b"img", &bad, &target).is_err());
    assert!(!target.exists());
    let leftovers: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".vpqc-tmp"))
        .collect();
    assert!(leftovers.is_empty(), "temporary files left: {leftovers:?}");

    // A failed decryption never replaces an existing output file.
    std::fs::write(&target, b"previous contents").unwrap();
    assert!(stream::decrypt_file(&kp.secret, b"wrong", &enc, &target).is_err());
    assert_eq!(std::fs::read(&target).unwrap(), b"previous contents");
}

/// Regression vector: fixed randomness gives a fixed stream. Protects the wire format across
/// versions and languages (self-generated, see ADR-0007). Regenerate only for a new format
/// version: `VPQC_WRITE_VECTORS=1 cargo test -p vpqc --test stream regression_vector`.
#[test]
fn regression_vector() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/stream-v1.json");
    let rnd: Vec<u8> = (0..512u32).map(|i| (i * 7 + 3) as u8).collect();
    let kp =
        encryption::generate_with(Profile::Standard, &mut FixedRandom::new(&rnd[..32])).unwrap();
    let pt = data(2 * CHUNK + 5);
    let mut e = Encryptor::with_rng(
        &kp.public,
        b"vector",
        Vec::new(),
        SMALL,
        &mut FixedRandom::new(&rnd[32..96]),
    )
    .unwrap();
    e.write_all(&pt).unwrap();
    let ct = e.finish().unwrap();
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let doc = serde_json::json!({
        "description": "vpqc stream v1 regression vector (ADR-0007). Self-generated.",
        "secret_key": hex(&vpqc::keys::secret_to_bytes(&kp.secret)),
        "aad": hex(b"vector"),
        "plaintext_len": pt.len(),
        "plaintext_rule": "byte i = (i * 31) mod 251",
        "ciphertext": hex(&ct),
    });
    if std::env::var_os("VPQC_WRITE_VECTORS").is_some() {
        std::fs::write(path, serde_json::to_string_pretty(&doc).unwrap() + "\n").unwrap();
    }
    let stored: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(
        stored, doc,
        "stream format changed: bump the format version instead"
    );
    assert_eq!(decrypt(&kp.secret, b"vector", &ct).unwrap(), pt);
}

fn push_decrypt(
    sk: &vpqc::SecretKey,
    aad: &[u8],
    ct: &[u8],
    split: &[usize],
) -> std::io::Result<Vec<u8>> {
    let mut d = stream::PushDecryptor::new(sk, aad);
    let mut out = Vec::new();
    let mut rest = ct;
    let mut i = 0;
    while !rest.is_empty() {
        let n = split[i % split.len()].min(rest.len());
        out.extend(d.update(&rest[..n])?);
        rest = &rest[n..];
        i += 1;
    }
    out.extend(d.finish()?);
    Ok(out)
}

#[test]
fn push_decryptor_matches_reader_for_any_split() {
    let kp = encryption::generate(Profile::Standard).unwrap();
    for n in [0, 1, CHUNK, CHUNK + 1, 3 * CHUNK, 3 * CHUNK + 77] {
        let pt = data(n);
        let ct = encrypt(&kp.public, b"p", &pt, SMALL);
        for split in [
            &[1usize][..],
            &[7, 1, 1500],
            &[CHUNK + 16],
            &[CHUNK + 17, 3],
            &[1 << 20],
        ] {
            assert_eq!(
                push_decrypt(&kp.secret, b"p", &ct, split).unwrap(),
                pt,
                "n={n} split={split:?}"
            );
        }
    }
}

#[test]
fn push_decryptor_rejects_tampering_truncation_and_extension() {
    let kp = encryption::generate(Profile::Standard).unwrap();
    let ct = encrypt(&kp.public, b"", &data(2 * CHUNK + 9), SMALL);
    for i in 0..ct.len() {
        let mut bad = ct.clone();
        bad[i] ^= 1;
        assert!(
            push_decrypt(&kp.secret, b"", &bad, &[333]).is_err(),
            "flip {i}"
        );
    }
    for len in 0..ct.len() {
        assert!(
            push_decrypt(&kp.secret, b"", &ct[..len], &[500]).is_err(),
            "truncated to {len}"
        );
    }
    let mut longer = ct.clone();
    longer.extend_from_slice(&[0u8; 5]);
    assert!(push_decrypt(&kp.secret, b"", &longer, &[64]).is_err());
    assert!(push_decrypt(&kp.secret, b"other", &ct, &[64]).is_err());
    // After a failure the decryptor stays failed.
    let mut d = stream::PushDecryptor::new(&kp.secret, b"");
    let mut bad = ct.clone();
    bad[2000] ^= 1;
    assert!(d.update(&bad).is_err());
    assert!(d.update(b"").is_err());
    assert!(d.finish().is_err());
}

#[test]
fn incremental_encryption_with_get_mut() {
    let kp = encryption::generate(Profile::Standard).unwrap();
    let pt = data(5 * CHUNK + 3);
    let mut e = Encryptor::with_options(&kp.public, b"", Vec::new(), SMALL).unwrap();
    let mut ct = std::mem::take(e.get_mut()); // header
    for piece in pt.chunks(700) {
        e.write_all(piece).unwrap();
        ct.extend(std::mem::take(e.get_mut()));
    }
    ct.extend(e.finish().unwrap());
    assert_eq!(decrypt(&kp.secret, b"", &ct).unwrap(), pt);
}
