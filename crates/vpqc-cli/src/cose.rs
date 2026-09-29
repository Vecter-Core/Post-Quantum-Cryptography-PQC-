//! `vpqc cose|cwt`: post-quantum COSE_Sign1 and CWT (ML-DSA, `AKP` COSE_Keys).
//!
//! Messages are binary CBOR. With `--base64` they are written as base64url text (no padding),
//! and on input base64url text is recognised automatically (a COSE message never starts with
//! an ASCII letter or digit: tag 18 encodes as 0xd2, an untagged message as 0x84).

use std::fs;
use std::path::{Path, PathBuf};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::{Subcommand, ValueEnum};
use serde_json::{Map, Value};
use vpqc_cose::cwt::{self, Claims, Validation};
use vpqc_cose::sign1::{self, ContentType, Headers};
use vpqc_cose::{Algorithm, SigningKey, VerifyingKey};

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
pub enum CoseCommand {
    /// Generate a key: the private COSE_Key goes to --out (mode 0600), the public one to --pub.
    Key {
        #[arg(long, value_enum, default_value = "ML-DSA-65")]
        alg: AlgArg,
        /// Private COSE_Key output file.
        #[arg(long)]
        out: PathBuf,
        /// Public COSE_Key output file.
        #[arg(long = "pub")]
        public: PathBuf,
        /// Overwrite existing files.
        #[arg(long)]
        force: bool,
    },
    /// Sign the input into a COSE_Sign1 (tag 18).
    Sign {
        /// Private COSE_Key file.
        #[arg(long)]
        key: PathBuf,
        /// Key identifier (protected header `kid`, UTF-8 bytes).
        #[arg(long)]
        kid: Option<String>,
        /// Content type: a CoAP Content-Format number or a media type.
        #[arg(long)]
        content_type: Option<String>,
        /// External AAD: authenticated, not transmitted; the verifier must give the same.
        #[arg(long, default_value = "")]
        aad: String,
        /// Leave the payload out of the message (the verifier supplies it).
        #[arg(long)]
        detached: bool,
        /// Write base64url text instead of binary.
        #[arg(long)]
        base64: bool,
        /// Output file (default: stdout).
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Payload file (default: stdin).
        input: Option<PathBuf>,
    },
    /// Verify a COSE_Sign1 and print its payload.
    Verify {
        /// Public COSE_Key file.
        #[arg(long)]
        key: PathBuf,
        /// External AAD used when signing.
        #[arg(long, default_value = "")]
        aad: String,
        /// The payload of a detached message.
        #[arg(long)]
        payload: Option<PathBuf>,
        /// Message file (default: stdin).
        input: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
pub enum CwtCommand {
    /// Sign a CWT; `iat` and `exp` are set from --ttl.
    Sign {
        /// Private COSE_Key file.
        #[arg(long)]
        key: PathBuf,
        /// Lifetime in seconds.
        #[arg(long, default_value_t = 3600)]
        ttl: u64,
        #[arg(long)]
        iss: Option<String>,
        #[arg(long)]
        sub: Option<String>,
        #[arg(long)]
        aud: Option<String>,
        /// Key identifier (protected header `kid`).
        #[arg(long)]
        kid: Option<String>,
        /// Write base64url text instead of binary.
        #[arg(long)]
        base64: bool,
        /// Output file (default: stdout).
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Verify a CWT and its claims; prints the registered claims as JSON.
    Verify {
        /// Public COSE_Key file.
        #[arg(long)]
        key: PathBuf,
        /// Required issuer.
        #[arg(long)]
        iss: Option<String>,
        /// This service's audience (required if the token has `aud`).
        #[arg(long)]
        aud: Option<String>,
        /// Allowed clock skew in seconds.
        #[arg(long, default_value_t = 60)]
        leeway: u64,
        /// Token file (default: stdin).
        input: Option<PathBuf>,
    },
}

fn alg(a: AlgArg) -> Algorithm {
    match a {
        AlgArg::MlDsa65 => Algorithm::MlDsa65,
        AlgArg::MlDsa87 => Algorithm::MlDsa87,
    }
}

fn read(path: &Path) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|e| format!("{}: {e}", path.display()))
}

fn signing_key(path: &Path) -> Result<SigningKey, String> {
    SigningKey::from_cose_key(&read(path)?).map_err(|e| format!("{}: {e}", path.display()))
}

fn verifying_key(path: &Path) -> Result<VerifyingKey, String> {
    VerifyingKey::from_cose_key(&read(path)?).map_err(|e| format!("{}: {e}", path.display()))
}

/// The message bytes: binary as is, or base64url text decoded.
fn message(input: &Option<PathBuf>) -> Result<Vec<u8>, String> {
    let raw = read_input(input)?;
    match raw.first() {
        Some(b) if b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_' => {
            let text = std::str::from_utf8(&raw).map_err(|_| "input is not base64url text")?;
            URL_SAFE_NO_PAD
                .decode(text.trim())
                .map_err(|_| "input is not valid base64url".into())
        }
        _ => Ok(raw),
    }
}

fn emit(output: &Option<PathBuf>, bytes: &[u8], base64: bool) -> CliResult {
    if base64 {
        write_output(
            output,
            format!("{}\n", URL_SAFE_NO_PAD.encode(bytes)).as_bytes(),
        )
    } else {
        write_output(output, bytes)
    }
}

fn content_type(ct: Option<String>) -> Option<ContentType> {
    ct.map(|c| match c.parse::<u16>() {
        Ok(n) => ContentType::Format(n.into()),
        Err(_) => ContentType::MediaType(c),
    })
}

pub fn cose(cmd: CoseCommand) -> CliResult {
    match cmd {
        CoseCommand::Key {
            alg: a,
            out,
            public,
            force,
        } => {
            let key = SigningKey::generate(alg(a)).map_err(|e| e.to_string())?;
            write_new(&out, &key.to_cose_key(), true, force)?;
            write_new(&public, &key.verifying_key().to_cose_key(), false, force)
        }
        CoseCommand::Sign {
            key,
            kid,
            content_type: ct,
            aad,
            detached,
            base64,
            output,
            input,
        } => {
            let key = signing_key(&key)?;
            let headers = Headers {
                kid: kid.map(String::into_bytes),
                content_type: content_type(ct),
            };
            let payload = read_input(&input)?;
            let msg = if detached {
                sign1::sign_detached(&key, &payload, &headers, aad.as_bytes())
            } else {
                sign1::sign(&key, &payload, &headers, aad.as_bytes())
            }
            .map_err(|e| e.to_string())?;
            emit(&output, &msg, base64)
        }
        CoseCommand::Verify {
            key,
            aad,
            payload,
            input,
        } => {
            let key = verifying_key(&key)?;
            let msg = message(&input)?;
            let verified = match payload {
                Some(p) => sign1::verify_detached(&msg, &read(&p)?, &key, aad.as_bytes()),
                None => sign1::verify(&msg, &key, aad.as_bytes()),
            }
            .map_err(|e| e.to_string())?;
            write_output(&None, &verified.payload)
        }
    }
}

pub fn cwt(cmd: CwtCommand) -> CliResult {
    match cmd {
        CwtCommand::Sign {
            key,
            ttl,
            iss,
            sub,
            aud,
            kid,
            base64,
            output,
        } => {
            let key = signing_key(&key)?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let claims = Claims {
                iss,
                sub,
                aud,
                iat: Some(now),
                exp: Some(now.saturating_add(ttl.min(i64::MAX as u64) as i64)),
                ..Claims::default()
            };
            let headers = Headers {
                kid: kid.map(String::into_bytes),
                content_type: None,
            };
            let token =
                cwt::encode_with(&key, &claims, &headers, &[]).map_err(|e| e.to_string())?;
            emit(&output, &token, base64)
        }
        CwtCommand::Verify {
            key,
            iss,
            aud,
            leeway,
            input,
        } => {
            let v = Validation {
                leeway,
                issuer: iss,
                audience: aud,
                ..Validation::default()
            };
            let claims = cwt::decode(&message(&input)?, &verifying_key(&key)?, &v)
                .map_err(|e| e.to_string())?;
            let mut out = Map::new();
            let mut put = |name: &str, v: Option<Value>| {
                if let Some(v) = v {
                    out.insert(name.into(), v);
                }
            };
            put("iss", claims.iss.map(Value::from));
            put("sub", claims.sub.map(Value::from));
            put("aud", claims.aud.map(Value::from));
            put("exp", claims.exp.map(Value::from));
            put("nbf", claims.nbf.map(Value::from));
            put("iat", claims.iat.map(Value::from));
            put(
                "cti",
                claims.cti.map(|c| Value::from(URL_SAFE_NO_PAD.encode(c))),
            );
            if !claims.other.is_empty() {
                put("other_claims", Some(claims.other.len().into()));
            }
            println!("{}", Value::Object(out));
            Ok(())
        }
    }
}
