//! End-to-end tests of the `vpqc` binary.

use std::path::Path;
use std::process::{Command, Output};

fn vpqc(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_vpqc"))
        .args(args)
        .output()
        .unwrap()
}

fn ok(args: &[&str]) -> Output {
    let out = vpqc(args);
    assert!(
        out.status.success(),
        "vpqc {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

fn p(path: &Path) -> &str {
    path.to_str().unwrap()
}

#[test]
fn encrypt_decrypt_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("alice");
    ok(&["keygen", "--purpose", "encrypt", "--out", p(&key)]);
    let pubkey = dir.path().join("alice.pub");
    let seckey = dir.path().join("alice.vpqc-secret");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&seckey).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "secret key must be private");
    }

    let plain = dir.path().join("plain.txt");
    std::fs::write(&plain, b"hello post-quantum world").unwrap();
    let sealed = dir.path().join("plain.sealed");
    ok(&[
        "seal",
        "--to",
        p(&pubkey),
        "--aad",
        "v1",
        "-o",
        p(&sealed),
        p(&plain),
    ]);

    let out = ok(&["open", "--key", p(&seckey), "--aad", "v1", p(&sealed)]);
    assert_eq!(out.stdout, b"hello post-quantum world");

    // Wrong aad and wrong key fail with a non-zero exit code.
    assert!(
        !vpqc(&["open", "--key", p(&seckey), "--aad", "v2", p(&sealed)])
            .status
            .success()
    );
    let other = dir.path().join("bob");
    ok(&["keygen", "--purpose", "encrypt", "--out", p(&other)]);
    let bob_sec = dir.path().join("bob.vpqc-secret");
    assert!(
        !vpqc(&["open", "--key", p(&bob_sec), "--aad", "v1", p(&sealed)])
            .status
            .success()
    );

    let info = ok(&["inspect", p(&sealed)]);
    assert!(String::from_utf8_lossy(&info.stdout).contains("X-Wing"));
}

#[test]
fn sign_verify_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("signer");
    ok(&["keygen", "--purpose", "sign", "--out", p(&key)]);
    let pubkey = dir.path().join("signer.pub");
    let seckey = dir.path().join("signer.vpqc-secret");
    let file = dir.path().join("release.tar");
    std::fs::write(&file, b"release bytes").unwrap();
    let sig = dir.path().join("release.sig");

    ok(&[
        "sign",
        "--key",
        p(&seckey),
        "--context",
        "app/release",
        "-o",
        p(&sig),
        p(&file),
    ]);
    ok(&[
        "verify",
        "--key",
        p(&pubkey),
        "--context",
        "app/release",
        "--sig",
        p(&sig),
        p(&file),
    ]);

    assert!(
        !vpqc(&[
            "verify",
            "--key",
            p(&pubkey),
            "--context",
            "app/other",
            "--sig",
            p(&sig),
            p(&file)
        ])
        .status
        .success()
    );
    std::fs::write(&file, b"tampered bytes").unwrap();
    assert!(
        !vpqc(&[
            "verify",
            "--key",
            p(&pubkey),
            "--context",
            "app/release",
            "--sig",
            p(&sig),
            p(&file)
        ])
        .status
        .success()
    );
}

#[test]
fn keygen_refuses_to_overwrite() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("k");
    ok(&["keygen", "--purpose", "sign", "--out", p(&key)]);
    assert!(
        !vpqc(&["keygen", "--purpose", "sign", "--out", p(&key)])
            .status
            .success()
    );
    ok(&["keygen", "--purpose", "sign", "--out", p(&key), "--force"]);
}

#[test]
fn fast_auth_inspect_warns_classical() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("fa");
    ok(&[
        "keygen",
        "--purpose",
        "sign",
        "--profile",
        "fast-auth",
        "--out",
        p(&key),
    ]);
    let info = ok(&["inspect", p(&dir.path().join("fa.pub"))]);
    assert!(String::from_utf8_lossy(&info.stdout).contains("CLASSICAL ONLY"));
}

#[test]
fn profiles_lists_all() {
    let out = ok(&["profiles"]);
    let text = String::from_utf8_lossy(&out.stdout);
    for name in ["standard", "fast-auth", "cnsa2", "high"] {
        assert!(text.contains(name));
    }
}

#[test]
fn scan_reports_and_gates() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("a.py"),
        "k = rsa.generate_private_key(65537, 2048)\n",
    )
    .unwrap();
    let out = ok(&["scan", p(dir.path())]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("QUANTUM-VULNERABLE") && text.contains("RSA"),
        "{text}"
    );

    // Gate: policy failure gives exit code 2.
    let gated = vpqc(&["scan", p(dir.path()), "--fail-on", "quantum-vulnerable"]);
    assert_eq!(gated.status.code(), Some(2));

    // A clean tree passes the gate; the CBOM is valid JSON.
    let clean = tempfile::tempdir().unwrap();
    std::fs::write(clean.path().join("b.py"), "x = 1\n").unwrap();
    ok(&["scan", p(clean.path()), "--fail-on", "weak"]);
    let cbom = ok(&["scan", p(dir.path()), "--format", "cbom"]);
    let v: serde_json::Value = serde_json::from_slice(&cbom.stdout).unwrap();
    assert_eq!(v["specVersion"], "1.6");
}

#[test]
fn encrypt_decrypt_streaming_files_and_pipes() {
    use std::io::Write;
    use std::process::Stdio;

    let dir = tempfile::tempdir().unwrap();
    ok(&[
        "keygen",
        "--purpose",
        "encrypt",
        "--out",
        p(&dir.path().join("k")),
    ]);
    let pubkey = dir.path().join("k.pub");
    let seckey = dir.path().join("k.vpqc-secret");
    let big: Vec<u8> = (0..1_500_000u32).map(|i| (i % 253) as u8).collect();
    let plain = dir.path().join("big.bin");
    std::fs::write(&plain, &big).unwrap();

    // File -> file.
    let enc = dir.path().join("big.bin.vpqc");
    ok(&[
        "encrypt",
        "--to",
        p(&pubkey),
        "--aad",
        "backup",
        "-o",
        p(&enc),
        p(&plain),
    ]);
    let info = ok(&["inspect", p(&enc)]);
    assert!(
        String::from_utf8_lossy(&info.stdout).contains("stream"),
        "{:?}",
        info
    );
    let out = dir.path().join("restored.bin");
    ok(&[
        "decrypt",
        "--key",
        p(&seckey),
        "--aad",
        "backup",
        "-o",
        p(&out),
        p(&enc),
    ]);
    assert_eq!(std::fs::read(&out).unwrap(), big);

    // Refuses to overwrite without --force.
    assert!(
        !vpqc(&[
            "decrypt",
            "--key",
            p(&seckey),
            "--aad",
            "backup",
            "-o",
            p(&out),
            p(&enc)
        ])
        .status
        .success()
    );
    ok(&[
        "decrypt",
        "--key",
        p(&seckey),
        "--aad",
        "backup",
        "-o",
        p(&out),
        "--force",
        p(&enc),
    ]);

    // Truncated input: non-zero exit and no output file.
    let cut = dir.path().join("cut.vpqc");
    let ct = std::fs::read(&enc).unwrap();
    std::fs::write(&cut, &ct[..ct.len() / 2]).unwrap();
    let never = dir.path().join("never.bin");
    let r = vpqc(&[
        "decrypt",
        "--key",
        p(&seckey),
        "--aad",
        "backup",
        "-o",
        p(&never),
        p(&cut),
    ]);
    assert!(!r.status.success());
    assert!(!never.exists());

    // stdin -> file with truncated input: failure, and neither output nor temp file remains.
    let never2 = dir.path().join("never2.bin");
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_vpqc"))
        .args([
            "decrypt",
            "--key",
            p(&seckey),
            "--aad",
            "backup",
            "-o",
            p(&never2),
        ])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&std::fs::read(&cut).unwrap())
        .unwrap();
    assert!(!child.wait_with_output().unwrap().status.success());
    assert!(!never2.exists());
    assert!(std::fs::read_dir(dir.path()).unwrap().all(|e| {
        !e.unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".vpqc-tmp")
    }));

    // stdin -> stdout in both directions.
    let bin = env!("CARGO_BIN_EXE_vpqc");
    let mut child = std::process::Command::new(bin)
        .args(["encrypt", "--to", p(&pubkey)])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let data = big.clone();
    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || stdin.write_all(&data).unwrap());
    let enc_out = child.wait_with_output().unwrap();
    writer.join().unwrap();
    assert!(enc_out.status.success());
    let mut child = std::process::Command::new(bin)
        .args(["decrypt", "--key", p(&seckey)])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let ct = enc_out.stdout.clone();
    let writer = std::thread::spawn(move || stdin.write_all(&ct).unwrap());
    let dec_out = child.wait_with_output().unwrap();
    writer.join().unwrap();
    assert!(dec_out.status.success());
    assert_eq!(dec_out.stdout, big);
}

#[test]
fn jose_jwk_jws_jwt() {
    let dir = tempfile::tempdir().unwrap();
    let private = dir.path().join("k.jwk");
    let public = dir.path().join("pub.jwk");
    let out = ok(&[
        "jwk",
        "generate",
        "--alg",
        "ML-DSA-87",
        "--out",
        p(&private),
    ]);
    std::fs::write(&public, &out.stdout).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&private).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "private JWK must be private");
    }
    let public_jwk: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(public_jwk["alg"], "ML-DSA-87");
    assert!(public_jwk.get("priv").is_none());
    let derived = ok(&["jwk", "public", p(&private)]);
    assert_eq!(derived.stdout, out.stdout);
    assert_eq!(
        ok(&["jwk", "thumbprint", p(&private)]).stdout,
        ok(&["jwk", "thumbprint", p(&public)]).stdout
    );

    let payload = dir.path().join("payload");
    std::fs::write(&payload, b"hello \x00 world").unwrap();
    let token = dir.path().join("token");
    std::fs::write(
        &token,
        ok(&["jws", "sign", "--key", p(&private), p(&payload)]).stdout,
    )
    .unwrap();
    assert_eq!(
        ok(&["jws", "verify", "--key", p(&public), p(&token)]).stdout,
        b"hello \x00 world"
    );
    // A private JWK is refused where a public key is expected.
    assert!(
        !vpqc(&["jws", "verify", "--key", p(&private), p(&token)])
            .status
            .success()
    );

    let claims = dir.path().join("claims.json");
    std::fs::write(&claims, br#"{"sub":"alice","aud":"api"}"#).unwrap();
    let jwt = dir.path().join("jwt");
    std::fs::write(
        &jwt,
        ok(&[
            "jwt",
            "sign",
            "--key",
            p(&private),
            "--ttl",
            "60",
            p(&claims),
        ])
        .stdout,
    )
    .unwrap();
    let verified = ok(&[
        "jwt",
        "verify",
        "--key",
        p(&public),
        "--aud",
        "api",
        p(&jwt),
    ]);
    let v: serde_json::Value = serde_json::from_slice(&verified.stdout).unwrap();
    assert_eq!(v["sub"], "alice");
    assert!(
        !vpqc(&["jwt", "verify", "--key", p(&public), p(&jwt)])
            .status
            .success(),
        "aud not checked"
    );
}

#[test]
fn encrypt_to_several_recipients() {
    let dir = tempfile::tempdir().unwrap();
    for (name, profile) in [
        ("user", "standard"),
        ("recovery", "high"),
        ("outsider", "standard"),
    ] {
        ok(&[
            "keygen",
            "--purpose",
            "encrypt",
            "--profile",
            profile,
            "--out",
            p(&dir.path().join(name)),
        ]);
    }
    let key = |n: &str, ext: &str| dir.path().join(format!("{n}.{ext}"));
    let input = dir.path().join("data");
    std::fs::write(&input, vec![7u8; 100_000]).unwrap();
    let enc = dir.path().join("data.vpqc");
    ok(&[
        "encrypt",
        "--to",
        p(&key("user", "pub")),
        "--to",
        p(&key("recovery", "pub")),
        "--aad",
        "bk",
        "-o",
        p(&enc),
        p(&input),
    ]);
    let described = String::from_utf8(ok(&["inspect", p(&enc)]).stdout).unwrap();
    assert!(described.contains("2 recipients"), "{described}");
    for n in ["user", "recovery"] {
        let out = dir.path().join(format!("out-{n}"));
        ok(&[
            "decrypt",
            "--key",
            p(&key(n, "vpqc-secret")),
            "--aad",
            "bk",
            "-o",
            p(&out),
            p(&enc),
        ]);
        assert_eq!(std::fs::read(&out).unwrap(), vec![7u8; 100_000]);
    }
    let out = dir.path().join("out-outsider");
    let r = vpqc(&[
        "decrypt",
        "--key",
        p(&key("outsider", "vpqc-secret")),
        "--aad",
        "bk",
        "-o",
        p(&out),
        p(&enc),
    ]);
    assert!(!r.status.success() && !out.exists());
    let dup = vpqc(&[
        "encrypt",
        "--to",
        p(&key("user", "pub")),
        "--to",
        p(&key("user", "pub")),
        "-o",
        p(&dir.path().join("d")),
        p(&input),
    ]);
    assert!(!dup.status.success());
}

#[test]
fn envelope_key_rotation_with_rewrap() {
    let dir = tempfile::tempdir().unwrap();
    for name in ["old", "new"] {
        ok(&[
            "keygen",
            "--purpose",
            "encrypt",
            "--out",
            p(&dir.path().join(name)),
        ]);
    }
    let f = |n: &str| dir.path().join(n);
    std::fs::write(f("data"), b"rotate the key, keep the data").unwrap();
    ok(&[
        "encrypt",
        "--envelope",
        "--to",
        p(&f("old.pub")),
        "--aad",
        "a",
        "-o",
        p(&f("v1")),
        p(&f("data")),
    ]);
    // A plain single-recipient file cannot be re-wrapped.
    ok(&[
        "encrypt",
        "--to",
        p(&f("old.pub")),
        "--aad",
        "a",
        "-o",
        p(&f("plain")),
        p(&f("data")),
    ]);
    let r = vpqc(&[
        "rewrap",
        "--key",
        p(&f("old.vpqc-secret")),
        "--to",
        p(&f("new.pub")),
        "--aad",
        "a",
        "-o",
        p(&f("x")),
        p(&f("plain")),
    ]);
    assert!(!r.status.success() && String::from_utf8_lossy(&r.stderr).contains("re-encrypt"));

    ok(&[
        "rewrap",
        "--key",
        p(&f("old.vpqc-secret")),
        "--to",
        p(&f("new.pub")),
        "--aad",
        "a",
        "-o",
        p(&f("v2")),
        p(&f("v1")),
    ]);
    ok(&[
        "decrypt",
        "--key",
        p(&f("new.vpqc-secret")),
        "--aad",
        "a",
        "-o",
        p(&f("out")),
        p(&f("v2")),
    ]);
    assert_eq!(
        std::fs::read(f("out")).unwrap(),
        b"rotate the key, keep the data"
    );
    assert!(
        !vpqc(&[
            "decrypt",
            "--key",
            p(&f("old.vpqc-secret")),
            "--aad",
            "a",
            "-o",
            p(&f("o2")),
            p(&f("v2"))
        ])
        .status
        .success()
    );
    // Refuses to overwrite without --force.
    assert!(
        !vpqc(&[
            "rewrap",
            "--key",
            p(&f("old.vpqc-secret")),
            "--to",
            p(&f("new.pub")),
            "--aad",
            "a",
            "-o",
            p(&f("v2")),
            p(&f("v1"))
        ])
        .status
        .success()
    );
}
