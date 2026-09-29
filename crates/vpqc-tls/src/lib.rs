//! Hybrid post-quantum TLS 1.3.
//!
//! TLS is **not** reimplemented here. This crate configures [rustls] with the aws-lc-rs
//! provider so that key exchange uses the hybrid group `X25519MLKEM768` (ML-KEM-768 + X25519,
//! the group deployed by major browsers and CDNs), and offers:
//!
//! * [`server_config`] / [`client_config`]: ready-made configurations with a [`KxPolicy`];
//! * [`proxy`]: a TLS-terminating reverse proxy and a TLS-originating forward proxy, so a
//!   service that cannot be changed gets hybrid TLS by running a sidecar next to it;
//! * [`probe`]: connect to a server and report which key exchange it negotiated.
//!
//! Key exchange is the part of TLS exposed to "harvest now, decrypt later" (roadmap tier T0).
//! Certificates stay classical for now: post-quantum certificates are not yet deployable on
//! the public web.

pub mod probe;
pub mod proxy;

use std::sync::Arc;

use rustls::crypto::{CryptoProvider, SupportedKxGroup, aws_lc_rs};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use rustls::{ClientConfig, NamedGroup, RootCertStore, ServerConfig};

pub use rustls;

/// Which key exchange groups are allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KxPolicy {
    /// Only hybrid groups (`X25519MLKEM768`, `SecP256r1MLKEM768`). Peers without
    /// post-quantum support fail the handshake. Implies TLS 1.3.
    RequireHybrid,
    /// Hybrid first, classical fallback (X25519, P-256, P-384) for old peers. The fallback is
    /// visible through [`is_post_quantum`] so it can be logged and measured.
    PreferHybrid,
}

/// Errors from configuration and proxying.
#[derive(Debug)]
pub enum Error {
    /// I/O failure (sockets, files).
    Io(std::io::Error),
    /// TLS failure.
    Tls(rustls::Error),
    /// Invalid configuration input.
    Config(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "I/O error: {e}"),
            Error::Tls(e) => write!(f, "TLS error: {e}"),
            Error::Config(e) => write!(f, "configuration error: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<rustls::Error> for Error {
    fn from(e: rustls::Error) -> Self {
        Error::Tls(e)
    }
}

/// Result alias.
pub type Result<T> = std::result::Result<T, Error>;

/// Whether a negotiated group resists quantum attackers (hybrid or pure ML-KEM).
pub fn is_post_quantum(group: NamedGroup) -> bool {
    matches!(
        u16::from(group),
        0x11ec | 0x11eb | 0x11ed | 0x0200 | 0x0201 | 0x0202
    )
}

/// Human-readable group name.
pub fn group_name(group: NamedGroup) -> String {
    match u16::from(group) {
        0x11ec => "X25519MLKEM768".into(),
        0x11eb => "SecP256r1MLKEM768".into(),
        0x11ed => "SecP384r1MLKEM1024".into(),
        0x0200 => "MLKEM512".into(),
        0x0201 => "MLKEM768".into(),
        0x0202 => "MLKEM1024".into(),
        _ => format!("{group:?}"),
    }
}

/// A rustls crypto provider (aws-lc-rs) restricted according to `policy`.
pub fn provider(policy: KxPolicy) -> Arc<CryptoProvider> {
    use aws_lc_rs::kx_group;
    let groups: Vec<&'static dyn SupportedKxGroup> = match policy {
        KxPolicy::RequireHybrid => vec![kx_group::X25519MLKEM768, kx_group::SECP256R1MLKEM768],
        KxPolicy::PreferHybrid => vec![
            kx_group::X25519MLKEM768,
            kx_group::SECP256R1MLKEM768,
            kx_group::X25519,
            kx_group::SECP256R1,
            kx_group::SECP384R1,
        ],
    };
    Arc::new(CryptoProvider {
        kx_groups: groups,
        ..aws_lc_rs::default_provider()
    })
}

static TLS13_ONLY: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];

fn versions(policy: KxPolicy) -> &'static [&'static rustls::SupportedProtocolVersion] {
    match policy {
        KxPolicy::RequireHybrid => TLS13_ONLY,
        KxPolicy::PreferHybrid => rustls::DEFAULT_VERSIONS,
    }
}

/// Load a PEM certificate chain.
pub fn load_certs(path: &std::path::Path) -> Result<Vec<CertificateDer<'static>>> {
    let certs = CertificateDer::pem_file_iter(path)
        .map_err(|e| Error::Config(format!("{}: {e}", path.display())))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| Error::Config(format!("{}: {e}", path.display())))?;
    if certs.is_empty() {
        return Err(Error::Config(format!(
            "{}: no certificates found",
            path.display()
        )));
    }
    Ok(certs)
}

/// Load a PEM private key (PKCS#8, PKCS#1 or SEC1).
pub fn load_key(path: &std::path::Path) -> Result<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_file(path)
        .map_err(|e| Error::Config(format!("{}: {e}", path.display())))
}

/// Server configuration with hybrid key exchange.
pub fn server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    policy: KxPolicy,
) -> Result<ServerConfig> {
    let mut cfg = ServerConfig::builder_with_provider(provider(policy))
        .with_protocol_versions(versions(policy))?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(cfg)
}

/// Client configuration with hybrid key exchange, trusting `roots`.
pub fn client_config(roots: RootCertStore, policy: KxPolicy) -> Result<ClientConfig> {
    Ok(ClientConfig::builder_with_provider(provider(policy))
        .with_protocol_versions(versions(policy))?
        .with_root_certificates(roots)
        .with_no_client_auth())
}

/// Build a root store from PEM files.
pub fn roots_from_pem(paths: &[std::path::PathBuf]) -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    for p in paths {
        for c in load_certs(p)? {
            roots.add(c).map_err(Error::Tls)?;
        }
    }
    Ok(roots)
}
