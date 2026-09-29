//! `vpqc x509`: post-quantum (ML-DSA) keys and certificates.

use std::fs;
use std::path::{Path, PathBuf};

use clap::{Subcommand, ValueEnum};
use vpqc_x509::{
    Algorithm, Certificate, CertificateParams, PrivateKey, PublicKey, Purpose, VerifyOptions,
    verify_chain,
};

use crate::{CliResult, write_new};

#[derive(Clone, Copy, ValueEnum)]
pub enum AlgArg {
    /// ML-DSA-65 (default).
    #[value(name = "ML-DSA-65")]
    MlDsa65,
    /// ML-DSA-87 (CNSA 2.0; recommended for long-lived CAs).
    #[value(name = "ML-DSA-87")]
    MlDsa87,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum PurposeArg {
    /// TLS server.
    Server,
    /// TLS client.
    Client,
    /// Code signing.
    CodeSigning,
}

impl From<PurposeArg> for Purpose {
    fn from(p: PurposeArg) -> Self {
        match p {
            PurposeArg::Server => Purpose::ServerAuth,
            PurposeArg::Client => Purpose::ClientAuth,
            PurposeArg::CodeSigning => Purpose::CodeSigning,
        }
    }
}

#[derive(Subcommand)]
pub enum X509Command {
    /// Generate an ML-DSA key: PKCS#8 PEM to --out (mode 0600), public key (SPKI PEM) to stdout.
    Key {
        #[arg(long, value_enum, default_value = "ML-DSA-65")]
        alg: AlgArg,
        /// Private key output file.
        #[arg(long)]
        out: PathBuf,
        /// Overwrite an existing file.
        #[arg(long)]
        force: bool,
    },
    /// Create a self-signed CA certificate.
    Ca {
        /// CA private key (PKCS#8 PEM).
        #[arg(long)]
        key: PathBuf,
        /// Common name, e.g. "Example Root CA".
        #[arg(long)]
        cn: String,
        /// Organization.
        #[arg(long)]
        org: Option<String>,
        /// Validity in days.
        #[arg(long, default_value_t = 3650)]
        days: u32,
        /// Maximum number of intermediate CAs below this one.
        #[arg(long)]
        path_len: Option<u8>,
        /// Output certificate (PEM).
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Issue a certificate signed by a CA, for a public key (SPKI PEM) or the public part of a
    /// private key.
    Issue {
        /// Issuing CA certificate (PEM).
        #[arg(long)]
        ca: PathBuf,
        /// Issuing CA private key (PKCS#8 PEM).
        #[arg(long)]
        ca_key: PathBuf,
        /// Subject public key (SPKI PEM) or private key (PKCS#8 PEM).
        #[arg(long)]
        subject_key: PathBuf,
        /// Common name.
        #[arg(long)]
        cn: String,
        /// DNS name for the subject alternative name (repeatable).
        #[arg(long)]
        dns: Vec<String>,
        /// Extended key usage (repeatable).
        #[arg(long, value_enum)]
        purpose: Vec<PurposeArg>,
        /// Issue an intermediate CA instead of an end-entity certificate.
        #[arg(long)]
        intermediate_ca: bool,
        /// Validity in days.
        #[arg(long, default_value_t = 90)]
        days: u32,
        /// Output certificate (PEM).
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Verify a certificate chain; prints the path from the leaf to the trust anchor.
    Verify {
        /// Trust anchor certificates (PEM, repeatable or bundles).
        #[arg(long, required = true)]
        ca: Vec<PathBuf>,
        /// Intermediate certificates (PEM, repeatable or bundles).
        #[arg(long)]
        chain: Vec<PathBuf>,
        /// Required DNS name.
        #[arg(long)]
        dns: Option<String>,
        /// Required purpose.
        #[arg(long, value_enum)]
        purpose: Option<PurposeArg>,
        /// Leaf certificate (PEM).
        leaf: PathBuf,
    },
}

fn text(path: &Path) -> Result<String, String> {
    fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))
}

fn at<T>(path: &Path, r: vpqc_x509::Result<T>) -> Result<T, String> {
    r.map_err(|e| format!("{}: {e}", path.display()))
}

fn private_key(path: &Path) -> Result<PrivateKey, String> {
    let pem = zeroize::Zeroizing::new(text(path)?);
    at(path, PrivateKey::from_pkcs8_pem(&pem))
}

fn certs(paths: &[PathBuf]) -> Result<Vec<Certificate>, String> {
    let mut out = Vec::new();
    for p in paths {
        out.extend(at(p, Certificate::all_from_pem(&text(p)?))?);
    }
    Ok(out)
}

pub fn run(cmd: X509Command) -> CliResult {
    match cmd {
        X509Command::Key { alg, out, force } => {
            let alg = match alg {
                AlgArg::MlDsa65 => Algorithm::MlDsa65,
                AlgArg::MlDsa87 => Algorithm::MlDsa87,
            };
            let key = PrivateKey::generate(alg).map_err(|e| e.to_string())?;
            write_new(&out, key.to_pkcs8_pem().as_bytes(), true, force)?;
            print!("{}", key.public_key().to_spki_pem());
            Ok(())
        }
        X509Command::Ca {
            key,
            cn,
            org,
            days,
            path_len,
            output,
        } => {
            let key = private_key(&key)?;
            let mut params = CertificateParams::ca(&cn, days);
            if let Some(o) = org {
                params = params.organization(&o);
            }
            if let Some(n) = path_len {
                params = params.path_len(n);
            }
            let cert = params.self_signed(&key).map_err(|e| e.to_string())?;
            write_new(&output, cert.to_pem().as_bytes(), false, false)
        }
        X509Command::Issue {
            ca,
            ca_key,
            subject_key,
            cn,
            dns,
            purpose,
            intermediate_ca,
            days,
            output,
        } => {
            let ca_cert = at(&ca, Certificate::from_pem(&text(&ca)?))?;
            let ca_key = private_key(&ca_key)?;
            let subject_text = zeroize::Zeroizing::new(text(&subject_key)?);
            let subject = if subject_text.contains("PRIVATE KEY") {
                at(&subject_key, PrivateKey::from_pkcs8_pem(&subject_text))?
                    .public_key()
                    .clone()
            } else {
                at(&subject_key, PublicKey::from_spki_pem(&subject_text))?
            };
            let mut params = if intermediate_ca {
                CertificateParams::ca(&cn, days)
            } else {
                CertificateParams::end_entity(&cn, days)
            };
            let names: Vec<&str> = dns.iter().map(String::as_str).collect();
            params = params.dns_names(&names);
            for p in purpose {
                params = params.purpose(p.into());
            }
            let cert = params
                .issue(&subject, &ca_cert, &ca_key)
                .map_err(|e| e.to_string())?;
            write_new(&output, cert.to_pem().as_bytes(), false, false)
        }
        X509Command::Verify {
            ca,
            chain,
            dns,
            purpose,
            leaf,
        } => {
            let leaf_cert = at(&leaf, Certificate::from_pem(&text(&leaf)?))?;
            let options = VerifyOptions {
                dns_name: dns,
                purpose: purpose.map(Into::into),
                ..VerifyOptions::default()
            };
            let path = verify_chain(&leaf_cert, &certs(&chain)?, &certs(&ca)?, &options)
                .map_err(|e| format!("{}: {e}", leaf.display()))?;
            for (i, c) in path.iter().enumerate() {
                println!("{i}: {}", c.subject().unwrap_or_default());
            }
            println!("OK");
            Ok(())
        }
    }
}
