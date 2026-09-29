//! Writes the seed corpus to fuzz/seeds/: `cargo test --manifest-path fuzz/Cargo.toml --test gen_corpus -- --ignored`.
//! Inputs follow each target's layout (see `vpqc_fuzz::Input`) and use the same deterministic keys.

use std::io::Write;
use std::path::Path;

use vpqc::stream::{Encryptor, StreamOptions};
use vpqc::{encryption, keys, signing};
use vpqc_fuzz::{enc_keys, sig_keys};

fn put(target: &str, name: &str, bytes: &[u8]) {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("seeds").join(target);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(name), bytes).unwrap();
}

fn framed(mode: u8, key: u8, extra: &[u8], field: &[u8], rest: &[u8]) -> Vec<u8> {
    let mut v = vec![mode, key];
    v.extend_from_slice(extra);
    v.push(field.len() as u8);
    v.extend_from_slice(field);
    v.extend_from_slice(rest);
    v
}

#[test]
#[ignore]
fn gen_corpus() {
    let msg: Vec<u8> = (0..3000u32).map(|i| (i * 7) as u8).collect();
    for (i, kp) in enc_keys().iter().enumerate() {
        let i8 = i as u8;
        let sealed = encryption::seal(&kp.public, &msg[..100], b"ctx").unwrap();
        put("sealed_box", &format!("valid-{i}"), &framed(0, i8, &[], b"ctx", &sealed));
        put("sealed_box", &format!("roundtrip-{i}"), &framed(1, i8, &[], b"ctx", &msg[..300]));
        put("parse_formats", &format!("sealed-{i}"), &sealed);
        put("parse_formats", &format!("pub-{i}"), &keys::public_to_bytes(&kp.public));
        put("parse_formats", &format!("pub-armor-{i}"), keys::public_to_text(&kp.public).as_bytes());

        for (j, chunk_log) in [10u8, 11].into_iter().enumerate() {
            let mut e = Encryptor::with_options(&kp.public, b"s", Vec::new(), StreamOptions { chunk_log }).unwrap();
            e.write_all(&msg).unwrap();
            let ct = e.finish().unwrap();
            put("stream", &format!("valid-{i}-{j}"), &framed(0, i8, &[7], b"s", &ct));
            put("parse_formats", &format!("stream-{i}-{j}"), &ct[..ct.len().min(1800)]);
        }
        put("stream", &format!("roundtrip-{i}"), &framed(1, i8, &[3], b"s", &msg));
        put("stream", &format!("roundtrip-multi-{i}"), &framed(0x81, i8, &[3], b"s", &msg[..700]));
        let other = &enc_keys()[(i + 1) % 4];
        let mut e = Encryptor::to_recipients(&[&kp.public, &other.public], b"s", Vec::new(), StreamOptions { chunk_log: 10 }).unwrap();
        e.write_all(&msg[..2100]).unwrap();
        let multi = e.finish().unwrap();
        put("stream", &format!("multi-{i}"), &framed(0, i8, &[2], b"s", &multi));
        put("parse_formats", &format!("multistream-{i}"), &multi);
    }
    for (i, kp) in sig_keys().iter().enumerate() {
        let i8 = i as u8;
        let sig = signing::sign(&kp.secret, b"fixed message", b"app/v1").unwrap();
        put("signatures", &format!("valid-{i}"), &framed(0, i8, &[], b"app/v1", &sig));
        put("signatures", &format!("roundtrip-{i}"), &framed(1, i8, &[], b"app/v1", b"release"));
        put("parse_formats", &format!("sig-{i}"), &sig);
        put("parse_formats", &format!("sec-{i}"), &keys::secret_to_bytes(&kp.secret));
    }
    for i in 0..4u8 {
        put("hpke", &format!("roundtrip-{i}"), &[1, i, i, i, 4, b'i', b'n', b'f', b'o', 3, b'a', b'a', b'd', b'x', b'y']);
    }
    for (i, key) in vpqc_fuzz::jose_keys().iter().enumerate() {
        let i8 = i as u8;
        let token = vpqc_jose::jws::sign(key, b"{\"exp\":2000000}", &serde_json::Map::new()).unwrap();
        put("jose", &format!("token-{i}"), &[[0, i8].as_slice(), token.as_bytes()].concat());
        put("jose", &format!("jwk-{i}"), &[[1, i8].as_slice(), key.to_jwk().as_bytes()].concat());
        put("jose", &format!("pubjwk-{i}"), &[[1, i8].as_slice(), key.verifying_key().to_jwk().as_bytes()].concat());
        put("jose", &format!("roundtrip-{i}"), &[2, i8, 7, 3, b'h', b'i']);
    }
    let (root, leaf) = vpqc_fuzz::x509_pki();
    put("x509", "root", root.der());
    put("x509", "leaf", leaf.der());
    put("x509", "leaf-pem", leaf.to_pem().as_bytes());
    let k = vpqc_x509::PrivateKey::from_seed(vpqc_x509::Algorithm::MlDsa87, &[0x43; 32]);
    put("x509", "pkcs8", &k.to_pkcs8_der());
    put("x509", "spki", &k.public_key().to_spki_der());
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../crates/vpqc-scan/tests/fixtures");
    for entry in std::fs::read_dir(fixtures).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().to_string();
        let sel = if name.ends_with(".der") { 0 } else { 1 };
        let mut v = vec![sel];
        v.extend(std::fs::read(entry.path()).unwrap());
        put("scan", &name, &v);
    }
    put("scan", "code", b"\x03k = rsa.generate_private_key(65537, 2048)\nctx.set_ecdh_curve('X25519MLKEM768')\n");
}
