//! Scanner behaviour: certificates, key files, code patterns, output formats.

use std::fs;
use std::path::Path;

use base64::{Engine, engine::general_purpose::STANDARD};
use vpqc_scan::{Options, Report, Risk, Source, scan_path, to_cbom, to_json, to_text};

fn fixtures() -> &'static Path {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures"))
}

fn scan_fixtures() -> Report {
    scan_path(fixtures(), &Options::default()).unwrap()
}

fn find<'a>(r: &'a Report, path_part: &str, algo_part: &str) -> &'a vpqc_scan::Finding {
    r.findings
        .iter()
        .find(|f| f.path.contains(path_part) && f.algorithm.contains(algo_part))
        .unwrap_or_else(|| {
            panic!(
                "no finding for {path_part} / {algo_part}: {:#?}",
                r.findings
            )
        })
}

#[test]
fn parses_certificates_exactly() {
    let r = scan_fixtures();

    let rsa = find(&r, "rsa2048-long.pem", "RSA-2048 public key");
    assert_eq!(rsa.source, Source::Certificate);
    assert_eq!(rsa.risk, Risk::QuantumVulnerable);
    assert!(rsa.long_lived, "valid until 2033");
    assert_eq!(rsa.tier, "T1");
    assert!(rsa.detail.contains("rsa.example.test"));

    let p256 = find(&r, "ec-p256-short.pem", "EC P-256 public key");
    assert!(!p256.long_lived, "30-day certificate is short-lived");
    assert_eq!(p256.tier, "T1/T2");

    assert!(find(&r, "ec-p384-long.pem", "EC P-384").long_lived);
    assert_eq!(
        find(&r, "ed25519-long.pem", "Ed25519 public key").risk,
        Risk::QuantumVulnerable
    );

    // SHA-1 signature on the certificate is flagged as weak in its own right.
    let weak = find(&r, "rsa2048-sha1.pem", "sha1WithRSAEncryption");
    assert_eq!(weak.risk, Risk::Weak);
    assert_eq!(weak.tier, "T4");
}

#[test]
fn parses_binary_der_certificates() {
    let r = scan_fixtures();
    let der = find(&r, "ec-p384-long.der", "EC P-384");
    assert_eq!(der.source, Source::Certificate);
}

#[test]
fn never_leaks_key_material() {
    let dir = tempfile::tempdir().unwrap();
    // A PKCS#8 wrapper for an Ed25519 key with a recognisable dummy 32-byte secret.
    let secret = [0xAB_u8; 32];
    let mut der = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
    ];
    der.extend_from_slice(&[0x04, 0x22, 0x04, 0x20]);
    der.extend_from_slice(&secret);
    let pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        STANDARD.encode(&der)
    );
    fs::write(dir.path().join("id.key"), pem).unwrap();

    let r = scan_path(dir.path(), &Options::default()).unwrap();
    let f = find(&r, "id.key", "Ed25519 private key");
    assert_eq!(f.source, Source::PrivateKey);
    for out in [to_text(&r, true), to_json(&r), to_cbom(&r)] {
        assert!(!out.contains(&STANDARD.encode(secret)), "secret leaked");
        assert!(!out.contains("ABABABAB"), "secret leaked");
        assert!(!out.contains(&STANDARD.encode(&der)), "encoded key leaked");
    }
}

#[test]
fn detects_openssh_and_legacy_private_keys() {
    let dir = tempfile::tempdir().unwrap();
    let s = |b: &[u8]| {
        let mut v = (b.len() as u32).to_be_bytes().to_vec();
        v.extend_from_slice(b);
        v
    };
    let mut blob = b"openssh-key-v1\0".to_vec();
    blob.extend(s(b"none"));
    blob.extend(s(b"none"));
    blob.extend(s(b""));
    blob.extend(1u32.to_be_bytes());
    let mut public = s(b"ssh-rsa");
    public.extend(s(&[1, 2, 3]));
    blob.extend(s(&public));
    blob.extend(s(&[9; 16]));
    let pem = format!(
        "-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----\n",
        STANDARD.encode(&blob)
    );
    fs::write(dir.path().join("id_rsa"), pem).unwrap();
    fs::write(
        dir.path().join("legacy.pem"),
        "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("ec.pem"),
        "-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n",
    )
    .unwrap();
    let mut pubkey = s(b"ssh-ed25519");
    pubkey.extend(s(&[7; 32]));
    fs::write(
        dir.path().join("authorized_keys"),
        format!("ssh-ed25519 {} me@host\n", STANDARD.encode(pubkey)),
    )
    .unwrap();

    let r = scan_path(dir.path(), &Options::default()).unwrap();
    assert_eq!(
        find(&r, "id_rsa", "RSA private key").source,
        Source::PrivateKey
    );
    find(&r, "legacy.pem", "RSA private key");
    find(&r, "ec.pem", "EC private key");
    let pk = find(&r, "authorized_keys", "Ed25519 SSH public key");
    assert_eq!(pk.line, Some(1));
}

#[test]
fn source_patterns_and_priorities() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("app.py"),
        "import hashlib\nkey = rsa.generate_private_key(65537, 2048)\nh = hashlib.md5(b'x')\nctx.set_ecdh_curve('prime256v1')\nc = AES-256-GCM\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("nginx.conf"),
        "ssl_protocols TLSv1 TLSv1.2 TLSv1.3;\nssl_ecdh_curve X25519MLKEM768:X25519;\n",
    )
    .unwrap();
    fs::write(dir.path().join("Main.java"), "KeyPairGenerator.getInstance(\"RSA\");\nCipher.getInstance(\"RSA/ECB/OAEPPadding\");\nKeyAgreement.getInstance(\"ECDH\");\n").unwrap();
    fs::write(
        dir.path().join("token.js"),
        "jwt.sign(p, k, { algorithm: 'RS256' }); // ES384 also\n",
    )
    .unwrap();

    let r = scan_path(dir.path(), &Options::default()).unwrap();
    let has = |file: &str, algo: &str| {
        r.findings
            .iter()
            .any(|f| f.path.ends_with(file) && f.algorithm.contains(algo))
    };

    assert!(has("app.py", "RSA"));
    assert!(has("app.py", "MD5"));
    assert!(has("app.py", "NIST/SECG curve"));
    assert!(has("app.py", "256-bit symmetric"));
    assert!(has("nginx.conf", "obsolete TLS"));
    // The hybrid group on the same line is recognised, and plain X25519 is not double-reported.
    assert!(has("nginx.conf", "hybrid key exchange"));
    assert!(
        !r.findings
            .iter()
            .any(|f| f.path.ends_with("nginx.conf") && f.algorithm.contains("X25519 /"))
    );

    let key_transport = r
        .findings
        .iter()
        .find(|f| f.path.ends_with("Main.java") && f.algorithm.contains("RSA encryption"))
        .unwrap();
    assert_eq!(
        key_transport.tier, "T0",
        "RSA key transport is the top priority"
    );
    let ecdh = r
        .findings
        .iter()
        .find(|f| f.path.ends_with("Main.java") && f.algorithm == "ECDH")
        .unwrap();
    assert_eq!(ecdh.tier, "T0");
    assert!(has("token.js", "RSA signature"));
    assert!(has("token.js", "ECDSA"));
    assert_eq!(r.worst(), Some(Risk::QuantumVulnerable));
}

#[test]
fn word_boundaries_avoid_false_positives() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("clean.txt.rs"),
        "// UNIVERSAL RESPONSE\nlet des = describe();\nlet sha10 = 1;\nlet ml_dsa_like = 0;\nfn rsaless() {}\nlet pool_size = 3;\n",
    )
    .unwrap();
    let r = scan_path(dir.path(), &Options::default()).unwrap();
    let names: Vec<_> = r.findings.iter().map(|f| f.algorithm.clone()).collect();
    assert!(r.findings.is_empty(), "false positives: {names:?}");
}

#[test]
fn post_quantum_usage_is_recognised() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("pq.go"),
        "kem := mlkem.GenerateKey768()\nvar _ = ML-DSA-65\n// uses Kyber768 draft\n",
    )
    .unwrap();
    let r = scan_path(dir.path(), &Options::default()).unwrap();
    assert!(r.count(Risk::PostQuantum) >= 2);
    assert_eq!(r.count(Risk::QuantumVulnerable), 0);
}

#[test]
fn skips_vendor_dirs_binaries_docs_and_symlinks() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join("node_modules/x")).unwrap();
    fs::write(dir.path().join("node_modules/x/a.js"), "RSA ECDSA").unwrap();
    fs::create_dir_all(dir.path().join(".git")).unwrap();
    fs::write(dir.path().join(".git/config"), "RSA").unwrap();
    fs::write(dir.path().join("README.md"), "We use RSA and ECDSA").unwrap();
    fs::write(dir.path().join("blob.dat"), [0u8, 1, 2, b'R', b'S', b'A']).unwrap();
    fs::write(dir.path().join("image.png"), "RSA").unwrap();
    #[cfg(unix)]
    {
        fs::write(dir.path().join("real.py"), "x = 'RSA'").unwrap();
        std::os::unix::fs::symlink(dir.path().join("real.py"), dir.path().join("link.py")).unwrap();
    }
    let r = scan_path(dir.path(), &Options::default()).unwrap();
    assert!(!r.findings.iter().any(|f| f.path.contains("node_modules")
        || f.path.contains(".git")
        || f.path.ends_with("README.md")
        || f.path.ends_with("blob.dat")));
    #[cfg(unix)]
    assert!(
        !r.findings.iter().any(|f| f.path.ends_with("link.py")),
        "symlinks are not followed"
    );

    let docs = scan_path(
        dir.path(),
        &Options {
            include_docs: true,
            ..Options::default()
        },
    )
    .unwrap();
    assert!(docs.findings.iter().any(|f| f.path.ends_with("README.md")));
}

#[test]
fn text_report_lists_priorities_and_hides_info_by_default() {
    let r = scan_fixtures();
    let t = to_text(&r, false);
    assert!(t.contains("QUANTUM-VULNERABLE"));
    assert!(t.contains("T1"));
    assert!(t.contains("What to do:"));
    assert!(!t.contains("INFORMATIONAL"));
    assert!(to_text(&r, true).len() >= t.len());
}

#[test]
fn json_and_cbom_are_valid_json() {
    let r = scan_fixtures();
    let j: serde_json::Value = serde_json::from_str(&to_json(&r)).unwrap();
    assert_eq!(j["tool"], "vpqc-scan");
    assert!(j["summary"]["quantumVulnerable"].as_u64().unwrap() >= 4);

    let c: serde_json::Value = serde_json::from_str(&to_cbom(&r)).unwrap();
    assert_eq!(c["bomFormat"], "CycloneDX");
    assert_eq!(c["specVersion"], "1.6");
    let comps = c["components"].as_array().unwrap();
    assert!(comps.iter().all(|x| x["type"] == "cryptographic-asset"));
    assert!(
        comps
            .iter()
            .any(|x| x["cryptoProperties"]["assetType"] == "certificate")
    );
    // bom-refs are unique.
    let mut refs: Vec<_> = comps
        .iter()
        .map(|x| x["bom-ref"].as_str().unwrap().to_string())
        .collect();
    let n = refs.len();
    refs.sort();
    refs.dedup();
    assert_eq!(refs.len(), n, "duplicate bom-ref");
}

#[test]
fn comments_are_skipped_unless_requested() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("a.rs"),
        "// we used to use RSA here\n/* ECDSA */\n# ECDH\n  * DiffieHellman\nlet k = 1;\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("b.rs"),
        "let a = \"RSA\"; // inline comment is not a comment line\n",
    )
    .unwrap();
    let r = scan_path(dir.path(), &Options::default()).unwrap();
    assert!(
        !r.findings.iter().any(|f| f.path.ends_with("a.rs")),
        "{:#?}",
        r.findings
    );
    assert!(r.findings.iter().any(|f| f.path.ends_with("b.rs")));
    let all = scan_path(
        dir.path(),
        &Options {
            include_comments: true,
            ..Options::default()
        },
    )
    .unwrap();
    assert!(
        all.findings
            .iter()
            .filter(|f| f.path.ends_with("a.rs"))
            .count()
            >= 4
    );
}

#[test]
fn exclude_skips_matching_paths() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join("legacy")).unwrap();
    fs::write(dir.path().join("legacy/old.py"), "x = \"RSA\"").unwrap();
    fs::write(dir.path().join("new.py"), "x = \"RSA\"").unwrap();
    let r = scan_path(
        dir.path(),
        &Options {
            exclude: vec!["legacy".into()],
            ..Options::default()
        },
    )
    .unwrap();
    assert!(r.findings.iter().all(|f| !f.path.contains("legacy")));
    assert!(r.findings.iter().any(|f| f.path.ends_with("new.py")));
}

#[test]
fn text_report_groups_occurrences() {
    let dir = tempfile::tempdir().unwrap();
    let body: String = (0..10).map(|i| format!("k{i} = \"RSA\"\n")).collect();
    fs::write(dir.path().join("many.py"), body).unwrap();
    let r = scan_path(dir.path(), &Options::default()).unwrap();
    let t = to_text(&r, false);
    assert!(t.contains("x10"), "{t}");
    assert!(t.contains("+7 more"), "{t}");
    assert_eq!(
        t.matches("many.py").count(),
        3,
        "only three example locations are printed"
    );
}

#[test]
fn max_file_size_is_respected() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("big.py"),
        format!("{}RSA\n", "x".repeat(4096)),
    )
    .unwrap();
    let r = scan_path(
        dir.path(),
        &Options {
            max_file_size: 1024,
            ..Options::default()
        },
    )
    .unwrap();
    assert!(r.findings.is_empty());
    assert_eq!(r.files_skipped, 1);
}

#[test]
fn ssh_kex_algorithms_are_audited() {
    let dir = tempfile::tempdir().unwrap();
    let etc = dir.path().join("etc/ssh");
    fs::create_dir_all(etc.join("sshd_config.d")).unwrap();
    fs::write(
        etc.join("sshd_config"),
        "Port 22\nKexAlgorithms curve25519-sha256,ecdh-sha2-nistp256\n# KexAlgorithms mlkem768x25519-sha256\n",
    )
    .unwrap();
    fs::write(
        etc.join("sshd_config.d/10-hardening.conf"),
        "kexalgorithms=-sntrup*,mlkem*\n",
    )
    .unwrap();
    fs::write(
        etc.join("sshd_config.d/20-ok.conf"),
        "KexAlgorithms +diffie-hellman-group14-sha256\nKexAlgorithms -sntrup*\n",
    )
    .unwrap();
    fs::write(
        etc.join("ssh_config"),
        "Host *\n  KexAlgorithms curve25519-sha256,mlkem768x25519-sha256\n",
    )
    .unwrap();
    // Non-ASCII text across the keyword length must not panic (found by the fuzzer).
    fs::write(
        etc.join("sshd_config.d/30-unicode.conf"),
        "# Cấu hình\nKexAlgorithmé x\nKexAlgorithmsé\nkexalgorithms\u{a0}curve25519-sha256\n",
    )
    .unwrap();
    // Not an SSH config: the same line is only matched by the generic patterns.
    fs::write(
        dir.path().join("notes.conf"),
        "KexAlgorithms mlkem768x25519-sha256\n",
    )
    .unwrap();

    let r = scan_path(dir.path(), &Options::default()).unwrap();
    let ssh: Vec<_> = r
        .findings
        .iter()
        .filter(|f| f.algorithm.starts_with("SSH "))
        .collect();
    assert_eq!(ssh.len(), 3, "{ssh:#?}");

    let classical = find(&r, "sshd_config", "SSH key exchange without post-quantum");
    assert_eq!(classical.line, Some(2));
    assert_eq!(classical.risk, Risk::QuantumVulnerable);
    assert_eq!(classical.tier, "T0");
    let removed = find(&r, "10-hardening.conf", "without post-quantum");
    assert!(
        removed.detail.contains("-sntrup*,mlkem*"),
        "{}",
        removed.detail
    );

    let client = find(&r, "etc/ssh/ssh_config", "SSH hybrid post-quantum");
    assert_eq!(client.risk, Risk::PostQuantum);
    assert!(client.detail.contains("not first"), "{}", client.detail);
    // The audited line is not reported again as plain curve25519 / ECDH.
    assert!(
        !r.findings
            .iter()
            .any(|f| f.path.ends_with("ssh_config") && !f.algorithm.starts_with("SSH ")),
        "{:#?}",
        r.findings
    );
    assert!(!r.findings.iter().any(|f| f.path.ends_with("20-ok.conf")));
    assert!(
        !r.findings
            .iter()
            .any(|f| f.path.ends_with("notes.conf") && f.algorithm.starts_with("SSH "))
    );
}
