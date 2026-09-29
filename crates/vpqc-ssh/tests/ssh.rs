//! Probing fake servers over real TCP, KEXINIT parsing and KexAlgorithms auditing.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

use vpqc_ssh::{KexAudit, KexClass, ProbeError, audit_kex_directive, parse_kexinit, probe};

const OPENSSH_96_KEX: &str = "sntrup761x25519-sha512@openssh.com,curve25519-sha256,\
curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,\
diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,\
diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,ext-info-s,\
kex-strict-s-v00@openssh.com";

fn name_list(out: &mut Vec<u8>, list: &str) {
    out.extend_from_slice(&(list.len() as u32).to_be_bytes());
    out.extend_from_slice(list.as_bytes());
}

fn kexinit_payload(kex: &str) -> Vec<u8> {
    let mut p = vec![20];
    p.extend_from_slice(&[0xab; 16]);
    name_list(&mut p, kex);
    name_list(&mut p, "ssh-ed25519,rsa-sha2-512");
    for _ in 0..2 {
        name_list(
            &mut p,
            "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com",
        );
    }
    for _ in 0..2 {
        name_list(&mut p, "hmac-sha2-256-etm@openssh.com");
    }
    for _ in 0..2 {
        name_list(&mut p, "none,zlib@openssh.com");
    }
    for _ in 0..2 {
        name_list(&mut p, "");
    }
    p.extend_from_slice(&[0, 0, 0, 0, 0]);
    p
}

fn packet(payload: &[u8]) -> Vec<u8> {
    // Pad so that 4 + 1 + payload + padding is a multiple of 8, with at least 4 bytes.
    let mut padding = 8 - (5 + payload.len()) % 8;
    if padding < 4 {
        padding += 8;
    }
    let mut out = ((1 + payload.len() + padding) as u32)
        .to_be_bytes()
        .to_vec();
    out.push(padding as u8);
    out.extend_from_slice(payload);
    out.extend(std::iter::repeat_n(0u8, padding));
    out
}

/// Serve `response` to one client (after reading its identification line), return the address.
fn fake_server(response: Vec<u8>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let mut line = Vec::new();
        let mut b = [0u8; 1];
        while s.read_exact(&mut b).is_ok() && b[0] != b'\n' {
            line.push(b[0]);
        }
        assert!(line.starts_with(b"SSH-2.0-vpqc_probe"));
        let _ = s.write_all(&response);
        thread::sleep(Duration::from_millis(200));
    });
    addr
}

fn probe_with(response: Vec<u8>) -> Result<vpqc_ssh::ServerOffer, ProbeError> {
    probe(&fake_server(response), Duration::from_secs(5))
}

#[test]
fn probes_an_openssh_like_server() {
    let mut resp = b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n".to_vec();
    resp.extend(packet(&kexinit_payload(OPENSSH_96_KEX)));
    let offer = probe_with(resp).unwrap();
    assert_eq!(
        offer.identification,
        "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13"
    );
    assert_eq!(offer.kexinit.kex.len(), 12);
    assert_eq!(
        offer.post_quantum_kex(),
        vec!["sntrup761x25519-sha512@openssh.com"]
    );
    assert!(!offer.offers_ml_kem());
    assert!(offer.strict_kex());
    assert_eq!(offer.kexinit.host_keys, ["ssh-ed25519", "rsa-sha2-512"]);
    assert_eq!(
        offer.kexinit.macs_server_to_client,
        ["hmac-sha2-256-etm@openssh.com"]
    );
}

#[test]
fn banner_lines_before_identification_are_skipped() {
    let mut resp = b"Welcome\r\nauthorised use only\n".to_vec();
    resp.extend_from_slice(b"SSH-2.0-OpenSSH_10.0\r\n");
    resp.extend(packet(&kexinit_payload(
        "mlkem768x25519-sha256,curve25519-sha256",
    )));
    let offer = probe_with(resp).unwrap();
    assert!(offer.offers_ml_kem());
    assert!(!offer.strict_kex());
    assert_eq!(offer.post_quantum_kex(), vec!["mlkem768x25519-sha256"]);
}

#[test]
fn classical_only_server() {
    let mut resp = b"SSH-2.0-dropbear_2022.83\r\n".to_vec();
    resp.extend(packet(&kexinit_payload(
        "curve25519-sha256,diffie-hellman-group14-sha256",
    )));
    let offer = probe_with(resp).unwrap();
    assert!(offer.post_quantum_kex().is_empty());
}

#[test]
fn protocol_errors_are_reported() {
    let cases: Vec<(Vec<u8>, &str)> = vec![
        (b"SSH-1.5-old\r\n".to_vec(), "SSH 1"),
        (vec![b'x'; 300], "line too long"),
        (
            [b"SSH-2.0-x\r\n".as_slice(), &[0, 0, 0, 1, 4]].concat(),
            "bad packet length",
        ),
        (
            [b"SSH-2.0-x\r\n".as_slice(), &[0xff, 0, 0, 0]].concat(),
            "bad packet length",
        ),
        (
            [b"SSH-2.0-x\r\n".as_slice(), &packet(&[21, 0, 0])].concat(),
            "not KEXINIT",
        ),
    ];
    for (resp, want) in cases {
        match probe_with(resp) {
            Err(ProbeError::Protocol(why)) => assert!(why.contains(want), "{why} / {want}"),
            other => panic!("expected {want}, got {other:?}"),
        }
    }
    // Server closes the connection early: an I/O error, not a panic or a hang.
    assert!(matches!(
        probe_with(b"SSH-2.0-x\r\n".to_vec()),
        Err(ProbeError::Io(_))
    ));
}

#[test]
fn silent_server_times_out() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    thread::spawn(move || {
        let (_s, _) = listener.accept().unwrap();
        thread::sleep(Duration::from_secs(3));
    });
    let start = std::time::Instant::now();
    assert!(matches!(
        probe(&addr, Duration::from_millis(300)),
        Err(ProbeError::Io(_))
    ));
    assert!(start.elapsed() < Duration::from_secs(2));
}

#[test]
fn kexinit_parsing_rejects_malformed_input() {
    let good = kexinit_payload("mlkem768x25519-sha256");
    let parsed = parse_kexinit(&good).unwrap();
    assert_eq!(parsed.kex, ["mlkem768x25519-sha256"]);
    // Every truncation fails.
    for n in 0..good.len() {
        assert!(parse_kexinit(&good[..n]).is_err(), "prefix {n}");
    }
    // Invalid names: empty entries, spaces, over-long names, non-ASCII.
    for kex in [
        "a,,b",
        ",a",
        "a,",
        "a b",
        &"x".repeat(65),
        "curve25519-sha256\u{e9}",
    ] {
        assert!(parse_kexinit(&kexinit_payload(kex)).is_err(), "{kex}");
    }
    // Lengths pointing past the end.
    let mut huge = good.clone();
    huge[17..21].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(parse_kexinit(&huge).is_err());
}

#[test]
fn kex_classification() {
    for (name, class) in [
        ("mlkem768x25519-sha256", KexClass::HybridMlKem),
        ("mlkem768nistp256-sha256", KexClass::HybridMlKem),
        ("mlkem1024nistp384-sha384", KexClass::HybridMlKem),
        ("sntrup761x25519-sha512", KexClass::HybridSntrup),
        ("sntrup761x25519-sha512@openssh.com", KexClass::HybridSntrup),
        ("curve25519-sha256", KexClass::Classical),
        ("ecdh-sha2-nistp384", KexClass::Classical),
        ("diffie-hellman-group1-sha1", KexClass::Weak),
        ("ext-info-c", KexClass::Marker),
        ("kex-strict-s-v00@openssh.com", KexClass::Marker),
        ("something-new@example.com", KexClass::Unknown),
    ] {
        assert_eq!(vpqc_ssh::classify_kex(name), class, "{name}");
    }
}

#[test]
fn kex_directive_audit() {
    assert!(matches!(
        audit_kex_directive("mlkem768x25519-sha256,curve25519-sha256"),
        KexAudit::PostQuantum { pq_first: true, .. }
    ));
    assert!(matches!(
        audit_kex_directive("curve25519-sha256,sntrup761x25519-sha512"),
        KexAudit::PostQuantum {
            pq_first: false,
            ..
        }
    ));
    assert!(matches!(
        audit_kex_directive("curve25519-sha256,ecdh-sha2-nistp256"),
        KexAudit::ClassicalOnly { .. }
    ));
    assert_eq!(
        audit_kex_directive("+diffie-hellman-group14-sha256"),
        KexAudit::KeepsDefault
    );
    assert_eq!(
        audit_kex_directive("^mlkem768x25519-sha256"),
        KexAudit::KeepsDefault
    );
    // Removing only some of the defaults keeps a hybrid in the list.
    assert_eq!(audit_kex_directive("-sntrup*"), KexAudit::KeepsDefault);
    assert!(matches!(
        audit_kex_directive("-sntrup*,mlkem*"),
        KexAudit::RemovesPostQuantum { .. }
    ));
    assert!(matches!(
        audit_kex_directive("-*"),
        KexAudit::RemovesPostQuantum { .. }
    ));
}
