//! `vpqc jwk|jws|jwt`: post-quantum JOSE (ML-DSA, `AKP` JWKs).

use std::fs;
use std::path::{Path, PathBuf};

use clap::{Subcommand, ValueEnum};
use serde_json::{Map, Value};
use vpqc_jose::jwt::{self, Validation};
use vpqc_jose::{Algorithm, SigningKey, VerifyingKey, jws};

use crate::{CliResult, read_input, write_new, write_output};

#[derive(Clone, Copy, ValueEnum)]
pub enum AlgArg {
    /// ML-DSA-65 (default).
    #[value(name = "ML-DSA-65")]
    MlDsa65,
    /// ML-DSA-87 (CNSA 2.0).
    #[value(name = "ML-DSA-87")]
    MlDsa87,
}

#[derive(Subcommand)]
pub enum JwkCommand {
    /// Generate a key: writes the private JWK to --out (mode 0600), prints the public JWK.
    Generate {
        #[arg(long, value_enum, default_value = "ML-DSA-65")]
        alg: AlgArg,
        /// Private JWK output file.
        #[arg(long)]
        out: PathBuf,
        /// Overwrite an existing file.
        #[arg(long)]
        force: bool,
    },
    /// Print the public JWK of a private JWK.
    Public {
        /// Private JWK file.
        key: PathBuf,
    },
    /// Print the RFC 7638 thumbprint of a public or private JWK.
    Thumbprint {
        /// JWK file.
        key: PathBuf,
    },
}

#[derive(Subcommand)]
pub enum JwsCommand {
    /// Sign the input into a compact JWS.
    Sign {
        /// Private JWK file.
        #[arg(long)]
        key: PathBuf,
        /// Header `kid` (default: the key's thumbprint).
        #[arg(long)]
        kid: Option<String>,
        /// Header `typ`.
        #[arg(long)]
        typ: Option<String>,
        /// Payload file (default: stdin).
        input: Option<PathBuf>,
    },
    /// Verify a compact JWS and print its payload.
    Verify {
        /// Public JWK file.
        #[arg(long)]
        key: PathBuf,
        /// File holding the token (default: stdin).
        input: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
pub enum JwtCommand {
    /// Sign a JSON claims object as a JWT; `iat` and `exp` are set from --ttl.
    Sign {
        /// Private JWK file.
        #[arg(long)]
        key: PathBuf,
        /// Lifetime in seconds.
        #[arg(long, default_value_t = 300)]
        ttl: u64,
        /// Claims JSON file (default: stdin).
        input: Option<PathBuf>,
    },
    /// Verify a JWT and its claims; prints the claims.
    Verify {
        /// Public JWK file.
        #[arg(long)]
        key: PathBuf,
        /// Required issuer.
        #[arg(long)]
        iss: Option<String>,
        /// This service's audience identifier (required if the token has `aud`).
        #[arg(long)]
        aud: Option<String>,
        /// Required header `typ`, e.g. at+jwt.
        #[arg(long)]
        typ: Option<String>,
        /// Allowed clock skew in seconds.
        #[arg(long, default_value_t = 60)]
        leeway: u64,
        /// File holding the token (default: stdin).
        input: Option<PathBuf>,
    },
}

fn alg(a: AlgArg) -> Algorithm {
    match a {
        AlgArg::MlDsa65 => Algorithm::MlDsa65,
        AlgArg::MlDsa87 => Algorithm::MlDsa87,
    }
}

fn read_text(path: &Path) -> Result<String, String> {
    fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))
}

fn signing_key(path: &Path) -> Result<SigningKey, String> {
    SigningKey::from_jwk(&read_text(path)?).map_err(|e| format!("{}: {e}", path.display()))
}

fn verifying_key(path: &Path) -> Result<VerifyingKey, String> {
    VerifyingKey::from_jwk(&read_text(path)?).map_err(|e| format!("{}: {e}", path.display()))
}

fn token(input: &Option<PathBuf>) -> Result<String, String> {
    let raw = read_input(input)?;
    let text = String::from_utf8(raw).map_err(|_| "token is not UTF-8".to_string())?;
    Ok(text.trim().to_owned())
}

pub fn jwk(cmd: JwkCommand) -> CliResult {
    match cmd {
        JwkCommand::Generate { alg: a, out, force } => {
            let key = SigningKey::generate(alg(a)).map_err(|e| e.to_string())?;
            write_new(&out, key.to_jwk().as_bytes(), true, force)?;
            println!("{}", key.verifying_key().to_jwk());
            Ok(())
        }
        JwkCommand::Public { key } => {
            println!("{}", signing_key(&key)?.verifying_key().to_jwk());
            Ok(())
        }
        JwkCommand::Thumbprint { key } => {
            let text = read_text(&key)?;
            let public = match SigningKey::from_jwk(&text) {
                Ok(k) => k.verifying_key(),
                Err(_) => VerifyingKey::from_jwk(&text).map_err(|e| e.to_string())?,
            };
            println!("{}", public.thumbprint());
            Ok(())
        }
    }
}

pub fn jws(cmd: JwsCommand) -> CliResult {
    match cmd {
        JwsCommand::Sign {
            key,
            kid,
            typ,
            input,
        } => {
            let key = signing_key(&key)?;
            let mut header = Map::new();
            let kid = kid.unwrap_or_else(|| key.verifying_key().thumbprint());
            header.insert("kid".into(), kid.into());
            if let Some(t) = typ {
                header.insert("typ".into(), t.into());
            }
            let token =
                jws::sign(&key, &read_input(&input)?, &header).map_err(|e| e.to_string())?;
            println!("{token}");
            Ok(())
        }
        JwsCommand::Verify { key, input } => {
            let verified =
                jws::verify(&token(&input)?, &verifying_key(&key)?).map_err(|e| e.to_string())?;
            write_output(&None, &verified.payload)
        }
    }
}

pub fn jwt(cmd: JwtCommand) -> CliResult {
    match cmd {
        JwtCommand::Sign { key, ttl, input } => {
            let key = signing_key(&key)?;
            let claims: Value =
                serde_json::from_slice(&read_input(&input)?).map_err(|e| format!("claims: {e}"))?;
            let Value::Object(claims) = claims else {
                return Err("claims must be a JSON object".into());
            };
            println!(
                "{}",
                jwt::encode(&key, claims, ttl).map_err(|e| e.to_string())?
            );
            Ok(())
        }
        JwtCommand::Verify {
            key,
            iss,
            aud,
            typ,
            leeway,
            input,
        } => {
            let validation = Validation {
                issuer: iss,
                audience: aud,
                typ,
                leeway,
                ..Validation::default()
            };
            let claims = jwt::decode(&token(&input)?, &verifying_key(&key)?, &validation)
                .map_err(|e| e.to_string())?;
            println!("{}", Value::Object(claims));
            Ok(())
        }
    }
}
