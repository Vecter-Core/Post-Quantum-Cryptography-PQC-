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
    for name in ["standard", "fast-auth", "cnsa2"] {
        assert!(text.contains(name));
    }
}
