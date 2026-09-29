//! Multi-recipient streams (ADR-0009): every recipient decrypts, nobody else does, and the
//! header (stanzas, MAC, parameters) cannot be modified or spliced.

use std::io::{Read, Write};

use vpqc::stream::{self, Decryptor, Encryptor, StreamOptions};
use vpqc::{Error, KeyPair, Profile, encryption, signing};
use vpqc_core::testing::FixedRandom;
use vpqc_format::{AnyStreamHeader, HeaderScan, MAX_RECIPIENTS};

const SMALL: StreamOptions = StreamOptions { chunk_log: 10 };
const CHUNK: usize = 1024;

fn data(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 31 % 251) as u8).collect()
}

fn keys(profiles: &[Profile]) -> Vec<KeyPair> {
    profiles
        .iter()
        .map(|p| encryption::generate(*p).unwrap())
        .collect()
}

fn encrypt(recipients: &[&KeyPair], aad: &[u8], pt: &[u8]) -> Vec<u8> {
    let pks: Vec<_> = recipients.iter().map(|k| &k.public).collect();
    let mut e = Encryptor::to_recipients(&pks, aad, Vec::new(), SMALL).unwrap();
    e.write_all(pt).unwrap();
    e.finish().unwrap()
}

fn decrypt(sk: &vpqc::SecretKey, aad: &[u8], ct: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut d = Decryptor::new(sk, aad, ct)?;
    let mut out = Vec::new();
    d.read_to_end(&mut out)?;
    Ok(out)
}

fn push_decrypt(
    sk: &vpqc::SecretKey,
    aad: &[u8],
    ct: &[u8],
    step: usize,
) -> std::io::Result<Vec<u8>> {
    let mut d = stream::PushDecryptor::new(sk, aad);
    let mut out = Vec::new();
    for piece in ct.chunks(step) {
        out.extend(d.update(piece)?);
    }
    out.extend(d.finish()?);
    Ok(out)
}

fn header_len(ct: &[u8]) -> usize {
    match AnyStreamHeader::scan(ct).unwrap() {
        HeaderScan::Complete(n) => n,
        HeaderScan::NeedAtLeast(_) => panic!("incomplete"),
    }
}

fn is_decryption_failure(e: &std::io::Error) -> bool {
    matches!(
        stream::crypto_error(e),
        Some(Error::DecryptionFailed | Error::Format(_))
    )
}

#[test]
fn every_recipient_of_any_profile_decrypts() {
    let ks = keys(&[
        Profile::Standard,
        Profile::High,
        Profile::Cnsa2,
        Profile::Standard,
    ]);
    let refs: Vec<_> = ks.iter().collect();
    for n in [0, 1, CHUNK, CHUNK + 1, 3 * CHUNK + 5] {
        let pt = data(n);
        let ct = encrypt(&refs, b"ctx", &pt);
        for k in &ks {
            assert_eq!(decrypt(&k.secret, b"ctx", &ct).unwrap(), pt);
            for step in [1, 7, 1000, ct.len()] {
                assert_eq!(push_decrypt(&k.secret, b"ctx", &ct, step).unwrap(), pt);
            }
        }
    }
}

#[test]
fn outsiders_wrong_context_and_wrong_key_kinds_fail() {
    let ks = keys(&[Profile::Standard, Profile::High]);
    let ct = encrypt(&[&ks[0], &ks[1]], b"ctx", b"secret");
    for outsider in keys(&[Profile::Standard, Profile::High, Profile::Cnsa2]) {
        assert!(is_decryption_failure(
            &decrypt(&outsider.secret, b"ctx", &ct).unwrap_err()
        ));
    }
    for k in &ks {
        assert!(is_decryption_failure(
            &decrypt(&k.secret, b"ctx2", &ct).unwrap_err()
        ));
        assert!(is_decryption_failure(
            &decrypt(&k.secret, b"", &ct).unwrap_err()
        ));
    }
    let signer = signing::generate(Profile::Standard).unwrap();
    assert!(decrypt(&signer.secret, b"ctx", &ct).is_err());
}

#[test]
fn recipient_list_rules() {
    let ks = keys(&[Profile::Standard; 2]);
    let one = [&ks[0].public];
    assert!(Encryptor::to_recipients(&[], b"", Vec::new(), SMALL).is_err());
    assert!(
        Encryptor::to_recipients(&[&ks[0].public, &ks[0].public], b"", Vec::new(), SMALL).is_err()
    );
    let signer = signing::generate(Profile::Standard).unwrap();
    assert!(
        Encryptor::to_recipients(&[&ks[0].public, &signer.public], b"", Vec::new(), SMALL).is_err()
    );
    assert!(Encryptor::to_recipients(&one, b"", Vec::new(), SMALL).is_ok());

    let many = keys(&[Profile::Standard; MAX_RECIPIENTS + 1]);
    let pks: Vec<_> = many.iter().map(|k| &k.public).collect();
    assert!(Encryptor::to_recipients(&pks, b"", Vec::new(), SMALL).is_err());
    let ct = {
        let mut e =
            Encryptor::to_recipients(&pks[..MAX_RECIPIENTS], b"a", Vec::new(), SMALL).unwrap();
        e.write_all(b"x").unwrap();
        e.finish().unwrap()
    };
    assert_eq!(
        decrypt(&many[MAX_RECIPIENTS - 1].secret, b"a", &ct).unwrap(),
        b"x"
    );
    assert!(decrypt(&many[MAX_RECIPIENTS].secret, b"a", &ct).is_err());
}

#[test]
fn header_fields_and_body_are_authenticated() {
    let ks = keys(&[Profile::Standard, Profile::Cnsa2]);
    let pt = data(2 * CHUNK + 3);
    let ct = encrypt(&[&ks[0], &ks[1]], b"ctx", &pt);
    let hl = header_len(&ct);
    // Every structural header byte (fixed part, stanza headers, wrapped keys, MAC); KEM
    // ciphertext bodies and the payload are sampled (debug builds are slow).
    let AnyStreamHeader::Multi(h) = AnyStreamHeader::decode_prefix(&ct).unwrap() else {
        panic!("multi")
    };
    let mut positions: Vec<usize> = (0..9).collect();
    let mut pos = 9;
    for st in &h.recipients {
        let ct_len = st.kem_ciphertext.len();
        positions.extend(pos..pos + 4);
        positions.extend((pos + 4..pos + 4 + ct_len).step_by(29));
        positions.extend(pos + 4 + ct_len..pos + 4 + ct_len + 48);
        pos += 4 + ct_len + 48;
    }
    positions.extend(pos..hl);
    assert_eq!(pos + 32, hl);
    positions.extend((hl..ct.len()).step_by(97));
    for i in positions {
        let mut bad = ct.clone();
        bad[i] ^= 0x01;
        for k in &ks {
            assert!(
                decrypt(&k.secret, b"ctx", &bad).is_err(),
                "byte {i} not authenticated"
            );
        }
    }
    for cut in [1, 6, 9, 13, hl - 1, hl, hl + 1, ct.len() - 1] {
        for k in &ks {
            assert!(
                decrypt(&k.secret, b"ctx", &ct[..cut]).is_err(),
                "truncation at {cut}"
            );
            assert!(
                push_decrypt(&k.secret, b"ctx", &ct[..cut], 5).is_err(),
                "push truncation at {cut}"
            );
        }
    }
    let mut extended = ct.clone();
    extended.push(0);
    assert!(decrypt(&ks[0].secret, b"ctx", &extended).is_err());
}

/// The attack the header MAC exists for: a malicious sender wraps a different file key for
/// B and encrypts the payload under B's key, hoping A and B see different contents (with a
/// payload also valid for A this would be an "invisible salamanders" partitioning attack).
/// The MAC is keyed with one file key only, so B must reject even though its stanza unwraps and
/// the payload decrypts under its key.
#[test]
fn partitioned_file_keys_are_rejected_by_the_header_mac() {
    let ks = keys(&[Profile::Standard, Profile::Standard]);
    let (k1, k2) = ([1u8; 32], [2u8; 32]);
    let forge = |mac_key: &[u8; 32], payload_key: &[u8; 32]| {
        let mut e = Encryptor::to_recipients_forged_for_testing(
            &[&ks[0].public, &ks[1].public],
            &[k1, k2],
            mac_key,
            payload_key,
            b"ctx",
            Vec::new(),
            SMALL,
        )
        .unwrap();
        e.write_all(b"only for B").unwrap();
        e.finish().unwrap()
    };
    // MAC and payload under A's key: A decrypts; B unwraps k2 and must reject via the MAC.
    let for_a = forge(&k1, &k1);
    assert_eq!(
        decrypt(&ks[0].secret, b"ctx", &for_a).unwrap(),
        b"only for B"
    );
    assert!(is_decryption_failure(
        &decrypt(&ks[1].secret, b"ctx", &for_a).unwrap_err()
    ));
    // MAC under A's key, payload under B's key: without the MAC check B would accept.
    let for_b = forge(&k1, &k2);
    assert!(is_decryption_failure(
        &decrypt(&ks[1].secret, b"ctx", &for_b).unwrap_err()
    ));
    assert!(is_decryption_failure(
        &push_decrypt(&ks[1].secret, b"ctx", &for_b, 3).unwrap_err()
    ));
    // Sanity: a consistent forgery (all keys equal) is an honest file.
    let honest = forge(&k2, &k2);
    let mut e = Encryptor::to_recipients_forged_for_testing(
        &[&ks[0].public, &ks[1].public],
        &[k2, k2],
        &k2,
        &k2,
        b"ctx",
        Vec::new(),
        SMALL,
    )
    .unwrap();
    e.write_all(b"same").unwrap();
    let consistent = e.finish().unwrap();
    assert_eq!(
        decrypt(&ks[0].secret, b"ctx", &consistent).unwrap(),
        b"same"
    );
    assert_eq!(
        decrypt(&ks[1].secret, b"ctx", &consistent).unwrap(),
        b"same"
    );
    assert!(decrypt(&ks[0].secret, b"ctx", &honest).is_err()); // A unwraps k1, MAC is k2's
}

/// Splice the stanza of recipient B from a second file into the first: B unwraps a different
/// file key than A. The header MAC (keyed with the file key) must make both reject, so no two
/// recipients can ever be shown different plaintexts for the same file.
#[test]
fn spliced_stanzas_are_rejected_by_everyone() {
    let ks = keys(&[Profile::Standard, Profile::Standard]);
    let one = encrypt(&[&ks[0], &ks[1]], b"ctx", b"version one");
    let two = encrypt(&[&ks[0], &ks[1]], b"ctx", b"version two");
    let (AnyStreamHeader::Multi(h1), AnyStreamHeader::Multi(h2)) = (
        AnyStreamHeader::decode_prefix(&one).unwrap(),
        AnyStreamHeader::decode_prefix(&two).unwrap(),
    ) else {
        panic!("expected multi-recipient headers")
    };
    let mut spliced = h1.clone();
    spliced.recipients[1] = h2.recipients[1].clone();
    let mut forged = spliced.encode().unwrap();
    forged.extend_from_slice(&one[header_len(&one)..]);
    for k in &ks {
        assert!(is_decryption_failure(
            &decrypt(&k.secret, b"ctx", &forged).unwrap_err()
        ));
    }
    // Reordering stanzas also changes the header.
    let mut swapped = h1.clone();
    swapped.recipients.swap(0, 1);
    let mut forged = swapped.encode().unwrap();
    forged.extend_from_slice(&one[header_len(&one)..]);
    assert!(decrypt(&ks[0].secret, b"ctx", &forged).is_err());
}

#[test]
fn file_api_and_single_recipient_compatibility() {
    let dir = tempfile::tempdir().unwrap();
    let ks = keys(&[Profile::Standard, Profile::High]);
    let input = dir.path().join("in");
    std::fs::write(&input, data(5000)).unwrap();
    let enc = dir.path().join("in.vpqc");
    stream::encrypt_file_multi(&[&ks[0].public, &ks[1].public], b"f", &input, &enc).unwrap();
    for (i, k) in ks.iter().enumerate() {
        let out = dir.path().join(format!("out{i}"));
        stream::decrypt_file(&k.secret, b"f", &enc, &out).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), data(5000));
    }
    // Single-recipient streams (kind 5) are still read by the same decryptors.
    let single = dir.path().join("single.vpqc");
    stream::encrypt_file(&ks[1].public, b"f", &input, &single).unwrap();
    let out = dir.path().join("single.out");
    stream::decrypt_file(&ks[1].secret, b"f", &single, &out).unwrap();
    assert_eq!(std::fs::read(&out).unwrap(), data(5000));
}

#[test]
fn header_scan_is_incremental_and_strict() {
    let ks = keys(&[Profile::Standard, Profile::High]);
    let ct = encrypt(&[&ks[0], &ks[1]], b"", b"x");
    let hl = header_len(&ct);
    for i in 0..hl {
        match AnyStreamHeader::scan(&ct[..i]).unwrap() {
            HeaderScan::NeedAtLeast(n) => assert!(n > i && n <= hl, "prefix {i}: {n}"),
            HeaderScan::Complete(_) => panic!("complete at {i}"),
        }
    }
    let mut zero = ct.clone();
    zero[8] = 0;
    assert!(AnyStreamHeader::scan(&zero).is_err());
    let mut many = ct.clone();
    many[8] = 33;
    assert!(AnyStreamHeader::scan(&many).is_err());
    let mut kind = ct.clone();
    kind[5] = 7;
    assert!(AnyStreamHeader::scan(&kind).is_err());
}

#[test]
fn regression_vector() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/multistream-v1.json"
    );
    let rnd: Vec<u8> = (0..4096u32).map(|i| (i * 13 + 5) as u8).collect();
    let a =
        encryption::generate_with(Profile::Standard, &mut FixedRandom::new(&rnd[..64])).unwrap();
    let b = encryption::generate_with(Profile::High, &mut FixedRandom::new(&rnd[64..128])).unwrap();
    let pt = data(2 * CHUNK + 5);
    let mut e = Encryptor::to_recipients_with_rng(
        &[&a.public, &b.public],
        b"vector",
        Vec::new(),
        SMALL,
        &mut FixedRandom::new(&rnd[128..]),
    )
    .unwrap();
    e.write_all(&pt).unwrap();
    let ct = e.finish().unwrap();
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let doc = serde_json::json!({
        "description": "vpqc multi-recipient stream v1 regression vector (ADR-0009). Self-generated.",
        "secret_keys": [
            hex(&vpqc::keys::secret_to_bytes(&a.secret)),
            hex(&vpqc::keys::secret_to_bytes(&b.secret)),
        ],
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
        "multi-recipient stream format changed: bump the format version instead"
    );
    assert_eq!(decrypt(&a.secret, b"vector", &ct).unwrap(), pt);
    assert_eq!(decrypt(&b.secret, b"vector", &ct).unwrap(), pt);
}
