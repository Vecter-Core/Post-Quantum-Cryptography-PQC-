//! `vpqc-tls-proxy`: hybrid post-quantum TLS sidecar.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use tokio::net::TcpListener;
use vpqc_tls::proxy::{ConnectionInfo, serve_forward, serve_reverse};
use vpqc_tls::rustls::pki_types::ServerName;
use vpqc_tls::{
    KxPolicy, client_config, load_certs, load_key, probe::probe, roots_from_pem, server_config,
};

#[derive(Parser)]
#[command(
    name = "vpqc-tls-proxy",
    version,
    about = "Hybrid post-quantum TLS 1.3 sidecar (X25519MLKEM768)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Terminate hybrid TLS and forward plaintext to a local backend.
    Server {
        /// Address to listen on, e.g. 0.0.0.0:8443.
        #[arg(long)]
        listen: SocketAddr,
        /// Plaintext backend, e.g. 127.0.0.1:8080.
        #[arg(long)]
        backend: SocketAddr,
        /// PEM certificate chain.
        #[arg(long)]
        cert: PathBuf,
        /// PEM private key.
        #[arg(long)]
        key: PathBuf,
        /// Also accept classical key exchange from old clients (logged as non-PQ).
        #[arg(long)]
        allow_classical: bool,
    },
    /// Accept plaintext locally and forward over hybrid TLS to an upstream server.
    Client {
        /// Local address to listen on, e.g. 127.0.0.1:9000.
        #[arg(long)]
        listen: SocketAddr,
        /// Upstream host:port.
        #[arg(long)]
        connect: String,
        /// Server name to verify in the upstream certificate.
        #[arg(long)]
        server_name: String,
        /// PEM file(s) with trusted CA certificates.
        #[arg(long, required = true)]
        ca: Vec<PathBuf>,
        /// Allow classical key exchange if the upstream does not support hybrid.
        #[arg(long)]
        allow_classical: bool,
    },
    /// Report which key exchange a TLS server negotiates.
    Probe {
        /// host:port.
        addr: String,
        /// Server name (SNI). Defaults to the host part of ADDR.
        #[arg(long)]
        server_name: Option<String>,
        /// Trusted CA PEM file(s). Without it the certificate is not verified (inventory only).
        #[arg(long)]
        ca: Vec<PathBuf>,
        /// Exit with status 2 if the negotiated key exchange is not post-quantum.
        #[arg(long)]
        require_pq: bool,
    },
}

fn policy(allow_classical: bool) -> KxPolicy {
    if allow_classical {
        KxPolicy::PreferHybrid
    } else {
        KxPolicy::RequireHybrid
    }
}

fn logger() -> Arc<dyn Fn(&ConnectionInfo) + Send + Sync> {
    Arc::new(|c: &ConnectionInfo| {
        let pq = if c.post_quantum {
            "post-quantum"
        } else {
            "CLASSICAL"
        };
        eprintln!(
            "vpqc-tls-proxy: {} {} {} [{pq}]",
            c.peer, c.version, c.group
        );
    })
}

async fn run(cli: Cli) -> Result<u8, String> {
    match cli.command {
        Command::Server {
            listen,
            backend,
            cert,
            key,
            allow_classical,
        } => {
            let cfg = server_config(
                load_certs(&cert).map_err(|e| e.to_string())?,
                load_key(&key).map_err(|e| e.to_string())?,
                policy(allow_classical),
            )
            .map_err(|e| e.to_string())?;
            let listener = TcpListener::bind(listen).await.map_err(|e| e.to_string())?;
            eprintln!(
                "vpqc-tls-proxy: {listen} (TLS, {:?}) -> {backend}",
                policy(allow_classical)
            );
            serve_reverse(listener, Arc::new(cfg), backend, logger())
                .await
                .map_err(|e| e.to_string())?;
            Ok(0)
        }
        Command::Client {
            listen,
            connect,
            server_name,
            ca,
            allow_classical,
        } => {
            let cfg = client_config(
                roots_from_pem(&ca).map_err(|e| e.to_string())?,
                policy(allow_classical),
            )
            .map_err(|e| e.to_string())?;
            let name = ServerName::try_from(server_name).map_err(|e| e.to_string())?;
            let listener = TcpListener::bind(listen).await.map_err(|e| e.to_string())?;
            eprintln!(
                "vpqc-tls-proxy: {listen} -> {connect} (TLS, {:?})",
                policy(allow_classical)
            );
            serve_forward(listener, Arc::new(cfg), connect, name, logger())
                .await
                .map_err(|e| e.to_string())?;
            Ok(0)
        }
        Command::Probe {
            addr,
            server_name,
            ca,
            require_pq,
        } => {
            let name = server_name.unwrap_or_else(|| {
                addr.rsplit_once(':')
                    .map(|(h, _)| h)
                    .unwrap_or(&addr)
                    .to_string()
            });
            let roots = if ca.is_empty() {
                None
            } else {
                Some(roots_from_pem(&ca).map_err(|e| e.to_string())?)
            };
            let r = probe(&addr, &name, roots, Duration::from_secs(10))
                .await
                .map_err(|e| e.to_string())?;
            println!("server        : {addr} ({name})");
            println!("version       : {}", r.version);
            println!("cipher suite  : {}", r.cipher_suite);
            println!(
                "key exchange  : {} [{}]",
                r.group,
                if r.post_quantum {
                    "post-quantum"
                } else {
                    "CLASSICAL: exposed to harvest-now-decrypt-later"
                }
            );
            println!(
                "certificate   : {}",
                if r.certificate_verified {
                    "verified"
                } else {
                    "NOT verified (inventory mode; pass --ca to verify)"
                }
            );
            Ok(if require_pq && !r.post_quantum { 2 } else { 0 })
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("vpqc-tls-proxy: {e}");
            ExitCode::FAILURE
        }
    }
}
