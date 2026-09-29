//! Secret key files: plain or protected (ADR-0013), loading and writing.
//!
//! Passphrases come from, in order: the file named by `VPQC_PASSPHRASE_FILE`, the variable
//! `VPQC_PASSPHRASE`, or a prompt on the terminal (asked twice for a new key).

use std::fs;
use std::path::Path;

use clap::Args;
use vpqc::protect::{self, KdfParams, KeyProvider, Protection};
use vpqc::{SecretKey, keys};
use vpqc_format::dearmor;
use zeroize::Zeroizing;

use crate::kms;

/// How to protect a secret key when writing it.
#[derive(Args, Clone, Default)]
pub struct ProtectArgs {
    /// Encrypt the secret key under a passphrase (Argon2id). The passphrase is read from
    /// VPQC_PASSPHRASE_FILE, VPQC_PASSPHRASE or the terminal.
    #[arg(long)]
    pub passphrase: bool,
    /// Encrypt the secret key under a key held by an external service, as PROVIDER:LABEL:
    /// systemd-creds:NAME, aws-kms:KEY-ID|ARN|alias/NAME, gcp-kms:projects/.../cryptoKeys/KEY,
    /// vault-transit:MOUNT/KEY.
    #[arg(long, conflicts_with = "passphrase", value_name = "PROVIDER:LABEL")]
    pub kms: Option<String>,
    /// Argon2id memory in MiB (8 to 1024) for --passphrase.
    #[arg(long, default_value_t = 64, value_name = "MIB")]
    pub kdf_memory: u32,
}

impl ProtectArgs {
    pub fn is_set(&self) -> bool {
        self.passphrase || self.kms.is_some()
    }
}

fn passphrase_from_env() -> Result<Option<Zeroizing<String>>, String> {
    if let Some(path) = std::env::var_os("VPQC_PASSPHRASE_FILE") {
        let text =
            Zeroizing::new(fs::read_to_string(&path).map_err(|e| {
                format!("VPQC_PASSPHRASE_FILE {}: {e}", Path::new(&path).display())
            })?);
        let line = text.strip_suffix('\n').unwrap_or(&text);
        let line = line.strip_suffix('\r').unwrap_or(line);
        return Ok(Some(Zeroizing::new(line.to_owned())));
    }
    Ok(std::env::var("VPQC_PASSPHRASE").ok().map(Zeroizing::new))
}

fn prompt(text: &str) -> Result<Zeroizing<String>, String> {
    rpassword::prompt_password(text)
        .map(Zeroizing::new)
        .map_err(|e| format!("cannot read the passphrase ({e}); set VPQC_PASSPHRASE_FILE"))
}

fn existing_passphrase(path: &Path) -> Result<Zeroizing<String>, String> {
    match passphrase_from_env()? {
        Some(p) => Ok(p),
        None => prompt(&format!("Passphrase for {}: ", path.display())),
    }
}

fn new_passphrase() -> Result<Zeroizing<String>, String> {
    let p = match passphrase_from_env()? {
        Some(p) => p,
        None => {
            let first = prompt("New passphrase: ")?;
            if *prompt("Repeat passphrase: ")? != *first {
                return Err("passphrases do not match".into());
            }
            first
        }
    };
    if p.is_empty() {
        return Err("empty passphrase".into());
    }
    if p.chars().count() < 12 {
        eprintln!("warning: passphrases shorter than 12 characters are easy to guess offline");
    }
    Ok(p)
}

/// Parse `PROVIDER:LABEL`.
fn provider(spec: &str) -> Result<(KeyProvider, &str), String> {
    let (name, label) = spec
        .split_once(':')
        .ok_or("--kms must be PROVIDER:LABEL, e.g. aws-kms:alias/vpqc")?;
    let provider = KeyProvider::from_name(name).map_err(|_| {
        format!("unknown provider {name:?} (systemd-creds, aws-kms, gcp-kms, vault-transit)")
    })?;
    Ok((provider, label))
}

/// The file content for `secret`: armored, protected as requested.
pub fn encode(secret: &SecretKey, how: &ProtectArgs) -> Result<Zeroizing<String>, String> {
    if how.passphrase {
        let params = KdfParams {
            memory_kib: how.kdf_memory.saturating_mul(1024),
            ..KdfParams::default()
        };
        let pass = new_passphrase()?;
        let bytes = protect::protect_with_passphrase(secret, pass.as_bytes(), params)
            .map_err(|e| e.to_string())?;
        Ok(Zeroizing::new(protect::to_text(&bytes)))
    } else if let Some(spec) = &how.kms {
        let (provider, label) = provider(spec)?;
        let kek = protect::generate_kek().map_err(|e| e.to_string())?;
        let wrapped = kms::wrap(provider, label, &*kek)?;
        // Prove that the service can unwrap it again before relying on it.
        if *kms::unwrap(provider, label, &wrapped)? != kek[..] {
            return Err(format!(
                "{}: unwrapping returned a different key",
                provider.name()
            ));
        }
        let bytes = protect::protect_with_kek(secret, &kek, provider, label, &wrapped)
            .map_err(|e| e.to_string())?;
        Ok(Zeroizing::new(protect::to_text(&bytes)))
    } else {
        Ok(Zeroizing::new(keys::secret_to_text(secret)))
    }
}

/// A short description of how a key file is protected, or `None` if it is not.
pub fn describe(bytes: &[u8]) -> Option<String> {
    let text_protected = std::str::from_utf8(bytes).is_ok_and(|t| {
        t.trim_start()
            .starts_with("-----BEGIN VPQC PROTECTED SECRET KEY")
    });
    if !text_protected && !protect::is_protected_secret_key(bytes) {
        return None;
    }
    Some(match protect::protection(bytes) {
        Ok(Protection::Passphrase {
            memory_kib,
            iterations,
            parallelism,
            ..
        }) => format!(
            "passphrase (Argon2id, {} MiB, {iterations} passes, {parallelism} lanes)",
            memory_kib / 1024
        ),
        Ok(Protection::External {
            provider, label, ..
        }) => format!("{} key {label}", provider.name()),
        Err(e) => format!("unreadable ({e})"),
    })
}

/// Load a secret key file, decrypting it if it is protected.
pub fn load(path: &Path) -> Result<SecretKey, String> {
    let raw = Zeroizing::new(fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?);
    let at = |e: vpqc::Error| format!("{}: {e}", path.display());
    if describe(&raw).is_some() {
        return match protect::protection(&raw).map_err(at)? {
            Protection::Passphrase { .. } => {
                let pass = existing_passphrase(path)?;
                protect::unprotect_with_passphrase(&raw, pass.as_bytes()).map_err(|e| match e {
                    vpqc::Error::DecryptionFailed => {
                        format!("{}: wrong passphrase or damaged file", path.display())
                    }
                    e => at(e),
                })
            }
            Protection::External {
                provider,
                label,
                wrapped,
            } => {
                let kek = kms::unwrap(provider, &label, &wrapped)?;
                protect::unprotect_with_kek(&raw, &kek).map_err(at)
            }
        };
    }
    let bytes = match std::str::from_utf8(&raw) {
        Ok(text) if text.trim_start().starts_with("-----BEGIN") => {
            Zeroizing::new(dearmor("VPQC SECRET KEY", text).map_err(at)?)
        }
        _ => Zeroizing::new(raw.to_vec()),
    };
    keys::secret_from_bytes(&bytes).map_err(at)
}
