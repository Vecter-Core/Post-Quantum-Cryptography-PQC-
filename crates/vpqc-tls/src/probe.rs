//! Report the key exchange a TLS server negotiates.

use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::{Error, KxPolicy, Result, group_name, is_post_quantum, provider};

/// Outcome of a probe.
#[derive(Debug, Clone)]
pub struct ProbeReport {
    /// Negotiated key exchange group.
    pub group: String,
    /// Whether it is post-quantum.
    pub post_quantum: bool,
    /// Protocol version.
    pub version: String,
    /// Cipher suite.
    pub cipher_suite: String,
    /// Whether the certificate chain was verified against the given roots.
    pub certificate_verified: bool,
}

/// Accepts any certificate. Used only by [`probe`] when the caller asks for an
/// inventory-only check without trust roots; the connection carries no application data.
#[derive(Debug)]
struct InventoryOnly(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for InventoryOnly {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Connect to `addr` (`host:port`), offer hybrid and classical groups, and report what the
/// server chose. With `roots = None` the certificate is **not** verified (inventory mode).
pub async fn probe(
    addr: &str,
    server_name: &str,
    roots: Option<rustls::RootCertStore>,
    timeout: Duration,
) -> Result<ProbeReport> {
    let prov = provider(KxPolicy::PreferHybrid);
    let verified = roots.is_some();
    let config = match roots {
        Some(r) => crate::client_config(r, KxPolicy::PreferHybrid)?,
        None => rustls::ClientConfig::builder_with_provider(prov.clone())
            .with_safe_default_protocol_versions()?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InventoryOnly(prov)))
            .with_no_client_auth(),
    };
    let name = ServerName::try_from(server_name.to_string())
        .map_err(|e| Error::Config(format!("server name: {e}")))?;
    let fut = async {
        let tcp = TcpStream::connect(addr).await?;
        let tls = TlsConnector::from(Arc::new(config))
            .connect(name, tcp)
            .await?;
        Ok::<_, Error>(tls)
    };
    let tls = tokio::time::timeout(timeout, fut).await.map_err(|_| {
        Error::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "probe timed out",
        ))
    })??;
    let conn = tls.get_ref().1;
    let group = conn.negotiated_key_exchange_group().map(|g| g.name());
    Ok(ProbeReport {
        group: group.map(group_name).unwrap_or_else(|| "none".into()),
        post_quantum: group.is_some_and(is_post_quantum),
        version: conn
            .protocol_version()
            .map(|v| format!("{v:?}"))
            .unwrap_or_default(),
        cipher_suite: conn
            .negotiated_cipher_suite()
            .map(|s| format!("{:?}", s.suite()))
            .unwrap_or_default(),
        certificate_verified: verified,
    })
}
