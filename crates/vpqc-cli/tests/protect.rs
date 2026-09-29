//! Protected secret keys through the CLI (ADR-0013): passphrase, and the external providers.
//!
//! `aws`, `gcloud` and `vault` are replaced by stand-ins on PATH that accept exactly the
//! argument list vpqc is expected to pass (and fail otherwise), and wrap reversibly. This
//! checks vpqc's side of each tool's contract, not the cloud services themselves.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct Env {
    dir: tempfile::TempDir,
}

impl Env {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("bin")).unwrap();
        for (name, script) in [
            ("aws", FAKE_AWS),
            ("gcloud", FAKE_GCLOUD),
            ("vault", FAKE_VAULT),
        ] {
            let path = dir.path().join("bin").join(name);
            std::fs::write(&path, script).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        std::fs::write(dir.path().join("pass"), "correct horse battery staple\n").unwrap();
        Env { dir }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn run(&self, args: &[&str], extra: &[(&str, &str)]) -> Output {
        let path = format!(
            "{}:{}",
            self.path("bin").display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_vpqc"));
        cmd.args(args)
            .current_dir(self.dir.path())
            .env("PATH", path)
            .env("FAKE_LOG", self.path("calls.log"))
            .env("VPQC_PASSPHRASE_FILE", self.path("pass"))
            .env_remove("VPQC_PASSPHRASE");
        for (k, v) in extra {
            cmd.env(k, v);
        }
        cmd.output().unwrap()
    }

    fn ok(&self, args: &[&str]) -> Output {
        let out = self.run(args, &[]);
        assert!(
            out.status.success(),
            "vpqc {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        out
    }

    fn calls(&self) -> String {
        std::fs::read_to_string(self.path("calls.log")).unwrap_or_default()
    }
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Encrypt to `name.pub`, decrypt with `key`: proves the protected key works end to end.
fn decrypts(env: &Env, name: &str, key: &str) {
    std::fs::write(env.path("m.txt"), b"hello").unwrap();
    env.ok(&[
        "encrypt",
        "--to",
        &format!("{name}.pub"),
        "-o",
        "m.vpqc",
        "--force",
        "m.txt",
    ]);
    let out = env.ok(&["decrypt", "--key", key, "m.vpqc"]);
    assert_eq!(out.stdout, b"hello");
}

#[test]
fn passphrase_protected_keys() {
    let env = Env::new();
    env.ok(&[
        "keygen",
        "--purpose",
        "encrypt",
        "--out",
        "a",
        "--passphrase",
        "--kdf-memory",
        "16",
    ]);
    let text = std::fs::read_to_string(env.path("a.vpqc-secret")).unwrap();
    assert!(text.starts_with("-----BEGIN VPQC PROTECTED SECRET KEY-----"));
    let mode = std::fs::metadata(env.path("a.vpqc-secret"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    let info = env.ok(&["inspect", "a.vpqc-secret"]);
    assert!(String::from_utf8_lossy(&info.stdout).contains("Argon2id, 16 MiB"));
    decrypts(&env, "a", "a.vpqc-secret");

    // Wrong passphrase, from the variable this time.
    std::fs::write(env.path("m.txt"), b"x").unwrap();
    env.ok(&[
        "encrypt", "--to", "a.pub", "-o", "m.vpqc", "--force", "m.txt",
    ]);
    let out = Command::new(env!("CARGO_BIN_EXE_vpqc"))
        .args(["decrypt", "--key", "a.vpqc-secret", "m.vpqc"])
        .current_dir(env.dir.path())
        .env_remove("VPQC_PASSPHRASE_FILE")
        .env("VPQC_PASSPHRASE", "wrong")
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("wrong passphrase"),
        "{}",
        stderr(&out)
    );

    // Unprotect gives back a plain key that works; protect can re-protect it.
    env.ok(&["unprotect", "a.vpqc-secret", "-o", "a.plain"]);
    assert!(
        std::fs::read_to_string(env.path("a.plain"))
            .unwrap()
            .starts_with("-----BEGIN VPQC SECRET KEY-----")
    );
    decrypts(&env, "a", "a.plain");
    env.ok(&[
        "protect",
        "a.plain",
        "--passphrase",
        "--kdf-memory",
        "8",
        "-o",
        "a.again",
    ]);
    decrypts(&env, "a", "a.again");
    // Out-of-range cost, and no protection method at all, are refused.
    assert!(
        !env.run(
            &[
                "protect",
                "a.plain",
                "--passphrase",
                "--kdf-memory",
                "4",
                "-o",
                "x"
            ],
            &[]
        )
        .status
        .success()
    );
    assert!(
        !env.run(&["protect", "a.plain", "-o", "y"], &[])
            .status
            .success()
    );
}

#[test]
fn kms_providers_follow_their_cli_contracts() {
    for (spec, program) in [
        ("aws-kms:alias/vpqc-test", "aws kms"),
        (
            "gcp-kms:projects/p/locations/global/keyRings/r/cryptoKeys/k",
            "gcloud kms",
        ),
        ("vault-transit:transit/vpqc", "vault write"),
    ] {
        let env = Env::new();
        env.ok(&[
            "keygen",
            "--purpose",
            "encrypt",
            "--out",
            "k",
            "--kms",
            spec,
        ]);
        let info =
            String::from_utf8_lossy(&env.ok(&["inspect", "k.vpqc-secret"]).stdout).into_owned();
        assert!(info.contains(spec.split_once(':').unwrap().0), "{info}");
        // keygen wraps, then unwraps once to check; decrypting unwraps again.
        decrypts(&env, "k", "k.vpqc-secret");
        let calls = env.calls();
        let count = |op: &str| {
            calls
                .lines()
                .filter(|l| l.contains(&format!(" {op} ")) || l.contains(&format!("/{op}/")))
                .count()
        };
        assert_eq!(count("encrypt"), 1, "{program}: {calls}");
        assert_eq!(count("decrypt"), 2, "{program}: {calls}");

        // A service returning a different key: protect refuses, loading fails.
        let broken = env.run(
            &[
                "keygen",
                "--purpose",
                "encrypt",
                "--out",
                "b",
                "--kms",
                spec,
            ],
            &[("FAKE_BROKEN", "1")],
        );
        assert!(!broken.status.success());
        assert!(
            stderr(&broken).contains("different key"),
            "{}",
            stderr(&broken)
        );
        std::fs::write(env.path("m.txt"), b"x").unwrap();
        env.ok(&[
            "encrypt", "--to", "k.pub", "-o", "m.vpqc", "--force", "m.txt",
        ]);
        let out = env.run(
            &["decrypt", "--key", "k.vpqc-secret", "m.vpqc"],
            &[("FAKE_BROKEN", "1")],
        );
        assert!(!out.status.success(), "{program}");
        // The service itself failing is reported.
        let out = env.run(
            &["decrypt", "--key", "k.vpqc-secret", "m.vpqc"],
            &[("FAKE_FAIL", "1")],
        );
        assert!(stderr(&out).contains("failed"), "{}", stderr(&out));
    }
}

#[test]
fn crafted_labels_are_refused() {
    let env = Env::new();
    env.ok(&["keygen", "--purpose", "sign", "--out", "s"]);
    for spec in [
        "vault-transit:transit/../sys/policy/x",
        "aws-kms:--endpoint-url=http://evil",
        "gcp-kms:a b",
        "systemd-creds:x;rm -rf /",
        "nope:label",
        "aws-kms",
    ] {
        let out = env.run(&["protect", "s.vpqc-secret", "--kms", spec, "-o", "p"], &[]);
        assert!(!out.status.success(), "{spec}");
    }
    assert_eq!(
        env.calls(),
        "",
        "no external command may run for a refused label"
    );
    assert!(!Path::new(&env.path("p")).exists());
}

const FAKE_AWS: &str = r#"#!/usr/bin/env python3
import base64, os, sys
a = sys.argv[1:]
open(os.environ["FAKE_LOG"], "a").write("aws " + " ".join(a) + "\n")
if os.environ.get("FAKE_FAIL"): sys.exit("AccessDeniedException")
common = ["--key-id=alias/vpqc-test", "--encryption-context=purpose=vpqc-secret-key"]
if a == ["kms", "encrypt", common[0], "--plaintext=fileb:///dev/stdin", common[1], "--query=CiphertextBlob", "--output=text"]:
    kek = sys.stdin.buffer.read()
    assert len(kek) == 32
    print(base64.b64encode(b"AWSKMS" + kek[::-1]).decode())
elif a == ["kms", "decrypt", common[0], "--ciphertext-blob=fileb:///dev/stdin", common[1], "--query=Plaintext", "--output=text"]:
    blob = sys.stdin.buffer.read()
    assert blob.startswith(b"AWSKMS")
    kek = blob[6:][::-1]
    if os.environ.get("FAKE_BROKEN"): kek = bytes(32)
    print(base64.b64encode(kek).decode())
else:
    sys.exit("unexpected arguments: %r" % a)
"#;

const FAKE_GCLOUD: &str = r#"#!/usr/bin/env python3
import os, sys
a = sys.argv[1:]
open(os.environ["FAKE_LOG"], "a").write("gcloud " + " ".join(a) + "\n")
if os.environ.get("FAKE_FAIL"): sys.exit("PERMISSION_DENIED")
key = "--key=projects/p/locations/global/keyRings/r/cryptoKeys/k"
if a == ["kms", "encrypt", key, "--plaintext-file=-", "--ciphertext-file=-"]:
    sys.stdout.buffer.write(b"GCP" + sys.stdin.buffer.read()[::-1])
elif a == ["kms", "decrypt", key, "--ciphertext-file=-", "--plaintext-file=-"]:
    blob = sys.stdin.buffer.read()
    assert blob.startswith(b"GCP")
    sys.stdout.buffer.write(bytes(32) if os.environ.get("FAKE_BROKEN") else blob[3:][::-1])
else:
    sys.exit("unexpected arguments: %r" % a)
"#;

const FAKE_VAULT: &str = r#"#!/usr/bin/env python3
import base64, os, sys
a = sys.argv[1:]
open(os.environ["FAKE_LOG"], "a").write("vault " + " ".join(a) + "\n")
if os.environ.get("FAKE_FAIL"): sys.exit("permission denied")
if a == ["write", "-field=ciphertext", "transit/encrypt/vpqc", "plaintext=-"]:
    kek = base64.b64decode(sys.stdin.read().strip())
    assert len(kek) == 32
    print("vault:v1:" + base64.b64encode(kek[::-1]).decode())
elif a == ["write", "-field=plaintext", "transit/decrypt/vpqc", "ciphertext=-"]:
    ct = sys.stdin.read().strip()
    assert ct.startswith("vault:v1:")
    kek = base64.b64decode(ct[9:])[::-1]
    if os.environ.get("FAKE_BROKEN"): kek = bytes(32)
    print(base64.b64encode(kek).decode())
else:
    sys.exit("unexpected arguments: %r" % a)
"#;
