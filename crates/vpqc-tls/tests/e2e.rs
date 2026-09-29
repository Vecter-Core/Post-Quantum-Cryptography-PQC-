//! End-to-end: real sockets, real handshakes, a plaintext echo backend behind the sidecar.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;
use vpqc_tls::proxy::{ConnectionInfo, serve_forward, serve_reverse};
use vpqc_tls::{KxPolicy, client_config, probe::probe, server_config};

struct Pki {
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}

fn pki() -> Pki {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    Pki {
        cert: ck.cert.der().clone(),
        key: PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der()).into(),
    }
}

fn roots(p: &Pki) -> RootCertStore {
    let mut r = RootCertStore::empty();
    r.add(p.cert.clone()).unwrap();
    r
}

/// A client that only offers classical X25519 (a legacy peer).
fn classical_client(p: &Pki) -> ClientConfig {
    let prov = rustls::crypto::CryptoProvider {
        kx_groups: vec![rustls::crypto::aws_lc_rs::kx_group::X25519],
        ..rustls::crypto::aws_lc_rs::default_provider()
    };
    ClientConfig::builder_with_provider(Arc::new(prov))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots(p))
        .with_no_client_auth()
}

async fn echo_backend() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    let n = match s.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    if s.write_all(&buf[..n]).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    addr
}

type Log = Arc<Mutex<Vec<ConnectionInfo>>>;

async fn reverse_proxy(p: &Pki, policy: KxPolicy, backend: SocketAddr) -> (SocketAddr, Log) {
    let cfg = server_config(vec![p.cert.clone()], p.key.clone_key(), policy).unwrap();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let log: Log = Arc::default();
    let sink = log.clone();
    tokio::spawn(serve_reverse(
        l,
        Arc::new(cfg),
        backend,
        Arc::new(move |c| sink.lock().unwrap().push(c.clone())),
    ));
    (addr, log)
}

async fn round_trip(cfg: ClientConfig, addr: SocketAddr) -> Result<(String, Vec<u8>), String> {
    let tcp = TcpStream::connect(addr).await.map_err(|e| e.to_string())?;
    let mut tls = TlsConnector::from(Arc::new(cfg))
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .map_err(|e| e.to_string())?;
    let group = vpqc_tls::group_name(
        tls.get_ref()
            .1
            .negotiated_key_exchange_group()
            .unwrap()
            .name(),
    );
    tls.write_all(b"ping over hybrid TLS")
        .await
        .map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; 20];
    tokio::time::timeout(Duration::from_secs(5), tls.read_exact(&mut buf))
        .await
        .map_err(|_| "timeout".to_string())?
        .map_err(|e| e.to_string())?;
    Ok((group, buf))
}

#[tokio::test]
async fn reverse_proxy_negotiates_x25519mlkem768() {
    let p = pki();
    let backend = echo_backend().await;
    let (addr, log) = reverse_proxy(&p, KxPolicy::RequireHybrid, backend).await;
    let (group, echoed) = round_trip(
        client_config(roots(&p), KxPolicy::RequireHybrid).unwrap(),
        addr,
    )
    .await
    .unwrap();
    assert_eq!(group, "X25519MLKEM768");
    assert_eq!(echoed, b"ping over hybrid TLS");
    let entry = log.lock().unwrap()[0].clone();
    assert!(entry.post_quantum);
    assert_eq!(entry.version, "TLSv1_3");
}

#[tokio::test]
async fn require_hybrid_rejects_classical_clients() {
    let p = pki();
    let backend = echo_backend().await;
    let (addr, log) = reverse_proxy(&p, KxPolicy::RequireHybrid, backend).await;
    let err = round_trip(classical_client(&p), addr).await.unwrap_err();
    assert!(!err.is_empty());
    assert!(
        log.lock().unwrap().is_empty(),
        "no connection may be forwarded"
    );
}

#[tokio::test]
async fn prefer_hybrid_falls_back_and_reports_it() {
    let p = pki();
    let backend = echo_backend().await;
    let (addr, log) = reverse_proxy(&p, KxPolicy::PreferHybrid, backend).await;
    let (group, _) = round_trip(classical_client(&p), addr).await.unwrap();
    assert_eq!(group, "X25519");
    assert!(
        !log.lock().unwrap()[0].post_quantum,
        "fallback must be visible"
    );
    // A capable client still gets the hybrid group.
    let (group, _) = round_trip(
        client_config(roots(&p), KxPolicy::PreferHybrid).unwrap(),
        addr,
    )
    .await
    .unwrap();
    assert_eq!(group, "X25519MLKEM768");
}

#[tokio::test]
async fn forward_proxy_upgrades_a_plaintext_client() {
    // legacy plaintext client -> forward sidecar -(hybrid TLS)-> reverse sidecar -> backend
    let p = pki();
    let backend = echo_backend().await;
    let (tls_addr, server_log) = reverse_proxy(&p, KxPolicy::RequireHybrid, backend).await;
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local = l.local_addr().unwrap();
    let cfg = client_config(roots(&p), KxPolicy::RequireHybrid).unwrap();
    let client_log: Log = Arc::default();
    let sink = client_log.clone();
    tokio::spawn(serve_forward(
        l,
        Arc::new(cfg),
        tls_addr.to_string(),
        ServerName::try_from("localhost").unwrap(),
        Arc::new(move |c| sink.lock().unwrap().push(c.clone())),
    ));
    let mut plain = TcpStream::connect(local).await.unwrap();
    plain.write_all(b"legacy app").await.unwrap();
    let mut buf = [0u8; 10];
    tokio::time::timeout(Duration::from_secs(5), plain.read_exact(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf, b"legacy app");
    assert!(client_log.lock().unwrap()[0].post_quantum);
    assert!(server_log.lock().unwrap()[0].post_quantum);
}

#[tokio::test]
async fn forward_proxy_rejects_untrusted_upstream() {
    let p = pki();
    let other = pki(); // a different CA: the upstream certificate is not trusted
    let backend = echo_backend().await;
    let (tls_addr, _) = reverse_proxy(&p, KxPolicy::RequireHybrid, backend).await;
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local = l.local_addr().unwrap();
    let log: Log = Arc::default();
    let sink = log.clone();
    tokio::spawn(serve_forward(
        l,
        Arc::new(client_config(roots(&other), KxPolicy::RequireHybrid).unwrap()),
        tls_addr.to_string(),
        ServerName::try_from("localhost").unwrap(),
        Arc::new(move |c| sink.lock().unwrap().push(c.clone())),
    ));
    let mut plain = TcpStream::connect(local).await.unwrap();
    let _ = plain.write_all(b"secret").await;
    let mut buf = [0u8; 6];
    let r = tokio::time::timeout(Duration::from_secs(5), plain.read_exact(&mut buf))
        .await
        .unwrap();
    assert!(r.is_err(), "data must not flow to an unverified upstream");
    assert!(log.lock().unwrap().is_empty());
}

#[tokio::test]
async fn probe_reports_group() {
    let p = pki();
    let backend = echo_backend().await;
    let (hybrid, _) = reverse_proxy(&p, KxPolicy::RequireHybrid, backend).await;
    let r = probe(
        &hybrid.to_string(),
        "localhost",
        Some(roots(&p)),
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert!(r.post_quantum && r.certificate_verified);
    assert_eq!(r.group, "X25519MLKEM768");

    // A classical-only server: the probe still connects and reports the downgrade.
    let prov = rustls::crypto::CryptoProvider {
        kx_groups: vec![rustls::crypto::aws_lc_rs::kx_group::X25519],
        ..rustls::crypto::aws_lc_rs::default_provider()
    };
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(prov))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![p.cert.clone()], p.key.clone_key())
        .unwrap();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let classical = l.local_addr().unwrap();
    tokio::spawn(serve_reverse(l, Arc::new(cfg), backend, Arc::new(|_| {})));
    let r = probe(
        &classical.to_string(),
        "localhost",
        None,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert!(!r.post_quantum && !r.certificate_verified);
    assert_eq!(r.group, "X25519");
}
