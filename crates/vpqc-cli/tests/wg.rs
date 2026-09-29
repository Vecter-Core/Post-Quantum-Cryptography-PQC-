//! `vpqc wg psk-seal` / `psk-open` without WireGuard itself (interop/wireguard.sh runs real
//! tunnels): both sides agree, the PSK is bound to the tunnel and the key, signatures work.

use std::path::Path;
use std::process::{Command, Output};

fn vpqc(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_vpqc"))
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap()
}

fn ok(dir: &Path, args: &[&str]) -> Output {
    let out = vpqc(dir, args);
    assert!(
        out.status.success(),
        "vpqc {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

// Three distinct 32-byte "WireGuard public keys" (only the encoding matters here).
const A: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";
const B: &str = "TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0=";
const C: &str = "gN65BkIKy1eCE9pP1wdc8ROUtkHLF2PfAqYdyYBz6EA=";

#[test]
fn psk_seal_open_signed_and_bound() {
    let t = tempfile::tempdir().unwrap();
    let d = t.path();
    ok(d, &["keygen", "--purpose", "encrypt", "--out", "bob"]);
    ok(d, &["keygen", "--purpose", "sign", "--out", "alice"]);
    ok(d, &["keygen", "--purpose", "sign", "--out", "eve"]);
    let open = |extra: &[&str], local: &str, peer: &str, input: &str, out: &str| {
        let mut args = vec![
            "wg",
            "psk-open",
            "--key",
            "bob.vpqc-secret",
            "--wg-local",
            local,
        ];
        args.extend_from_slice(&["--wg-peer", peer, "-o", out]);
        args.extend_from_slice(extra);
        args.push(input);
        vpqc(d, &args)
    };

    // Unsigned, binary.
    ok(
        d,
        &[
            "wg",
            "psk-seal",
            "--to",
            "bob.pub",
            "--wg-local",
            A,
            "--wg-peer",
            B,
            "--psk-out",
            "a.psk",
            "-o",
            "s",
        ],
    );
    assert!(open(&[], B, A, "s", "b.psk").status.success());
    let a = std::fs::read_to_string(d.join("a.psk")).unwrap();
    assert_eq!(a, std::fs::read_to_string(d.join("b.psk")).unwrap());
    assert_eq!(a.trim().len(), 44, "WireGuard base64 key");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(d.join("b.psk"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    // Bound to the tunnel: other WireGuard keys fail; equal keys are refused.
    assert!(!open(&[], B, C, "s", "x.psk").status.success());
    assert!(
        !vpqc(
            d,
            &[
                "wg",
                "psk-seal",
                "--to",
                "bob.pub",
                "--wg-local",
                A,
                "--wg-peer",
                A,
                "--psk-out",
                "y",
                "-o",
                "z"
            ]
        )
        .status
        .success()
    );
    assert!(
        !vpqc(
            d,
            &[
                "wg",
                "psk-seal",
                "--to",
                "bob.pub",
                "--wg-local",
                "short",
                "--wg-peer",
                B,
                "--psk-out",
                "y",
                "-o",
                "z"
            ]
        )
        .status
        .success()
    );

    // Signed, base64 text.
    let sealed = ok(
        d,
        &[
            "wg",
            "psk-seal",
            "--to",
            "bob.pub",
            "--wg-local",
            A,
            "--wg-peer",
            B,
            "--psk-out",
            "c.psk",
            "--sign-key",
            "alice.vpqc-secret",
            "--base64",
        ],
    );
    std::fs::write(d.join("signed.txt"), &sealed.stdout).unwrap();
    assert!(
        open(&["--from", "alice.pub"], B, A, "signed.txt", "d.psk")
            .status
            .success()
    );
    assert_eq!(
        std::fs::read(d.join("c.psk")).unwrap(),
        std::fs::read(d.join("d.psk")).unwrap()
    );
    assert!(
        !open(&["--from", "eve.pub"], B, A, "signed.txt", "e.psk")
            .status
            .success()
    );
    assert!(
        !open(&[], B, A, "signed.txt", "f.psk").status.success(),
        "signed needs --from"
    );
    assert!(
        !open(&["--from", "alice.pub"], B, A, "s", "g.psk")
            .status
            .success(),
        "unsigned with --from"
    );
    for f in ["x.psk", "e.psk", "f.psk", "g.psk"] {
        assert!(!d.join(f).exists(), "{f} written on failure");
    }
}
