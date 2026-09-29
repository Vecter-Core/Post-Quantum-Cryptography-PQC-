//! Sidecar proxies.
//!
//! * [`serve_reverse`]: accept hybrid TLS, forward plaintext to a local backend (put it in
//!   front of a service that speaks plain TCP/HTTP).
//! * [`serve_forward`]: accept plaintext locally, forward over hybrid TLS to a remote server
//!   (for a legacy client that cannot be upgraded).

use std::net::SocketAddr;
use std::sync::Arc;

use rustls::pki_types::ServerName;
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::{Result, group_name, is_post_quantum};

/// Summary of one proxied connection, for logging.
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    /// Peer address.
    pub peer: SocketAddr,
    /// Negotiated key exchange group.
    pub group: String,
    /// Whether the key exchange is post-quantum.
    pub post_quantum: bool,
    /// Negotiated protocol version.
    pub version: String,
}

fn describe(peer: SocketAddr, conn: &rustls::CommonState) -> ConnectionInfo {
    let group = conn.negotiated_key_exchange_group().map(|g| g.name());
    ConnectionInfo {
        peer,
        group: group.map(group_name).unwrap_or_else(|| "none".into()),
        post_quantum: group.is_some_and(is_post_quantum),
        version: conn
            .protocol_version()
            .map(|v| format!("{v:?}"))
            .unwrap_or_default(),
    }
}

/// Run a TLS-terminating reverse proxy until `listener` fails. `on_connect` is called after
/// each handshake (use it for logging/metrics).
pub async fn serve_reverse(
    listener: TcpListener,
    config: Arc<rustls::ServerConfig>,
    backend: SocketAddr,
    on_connect: Arc<dyn Fn(&ConnectionInfo) + Send + Sync>,
) -> Result<()> {
    let acceptor = TlsAcceptor::from(config);
    loop {
        let (tcp, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let on_connect = on_connect.clone();
        tokio::spawn(async move {
            let mut tls = match acceptor.accept(tcp).await {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("vpqc-tls-proxy: handshake from {peer} failed: {e}");
                    return;
                }
            };
            on_connect(&describe(peer, tls.get_ref().1));
            match TcpStream::connect(backend).await {
                Ok(mut up) => {
                    let _ = copy_bidirectional(&mut tls, &mut up).await;
                }
                Err(e) => eprintln!("vpqc-tls-proxy: backend {backend} unreachable: {e}"),
            }
        });
    }
}

/// Run a TLS-originating forward proxy: plaintext in on `listener`, hybrid TLS out to
/// `upstream`, verifying the server certificate for `server_name`.
pub async fn serve_forward(
    listener: TcpListener,
    config: Arc<rustls::ClientConfig>,
    upstream: String,
    server_name: ServerName<'static>,
    on_connect: Arc<dyn Fn(&ConnectionInfo) + Send + Sync>,
) -> Result<()> {
    let connector = TlsConnector::from(config);
    loop {
        let (mut local, peer) = listener.accept().await?;
        let connector = connector.clone();
        let upstream = upstream.clone();
        let name = server_name.clone();
        let on_connect = on_connect.clone();
        tokio::spawn(async move {
            let tcp = match TcpStream::connect(&upstream).await {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("vpqc-tls-proxy: upstream {upstream} unreachable: {e}");
                    return;
                }
            };
            let mut tls = match connector.connect(name, tcp).await {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("vpqc-tls-proxy: TLS to {upstream} failed: {e}");
                    return;
                }
            };
            on_connect(&describe(peer, tls.get_ref().1));
            let _ = copy_bidirectional(&mut local, &mut tls).await;
        });
    }
}
