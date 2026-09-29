//! Key-encryption key wrapping through external systems (ADR-0013), by running their official
//! command-line tools with a fixed argument list (no shell). The tools handle authentication
//! (AWS profiles and roles, gcloud accounts, VAULT_TOKEN, TPM access).
//!
//! | provider        | label                                   | wrap / unwrap                      |
//! |-----------------|-----------------------------------------|------------------------------------|
//! | `systemd-creds` | credential name                         | `systemd-creds encrypt/decrypt`    |
//! | `aws-kms`       | key id, ARN or `alias/...`              | `aws kms encrypt/decrypt`          |
//! | `gcp-kms`       | `projects/.../cryptoKeys/KEY`           | `gcloud kms encrypt/decrypt`       |
//! | `vault-transit` | `MOUNT/KEY`, e.g. `transit/vpqc`        | `vault write MOUNT/encrypt|decrypt` |
//!
//! Labels come from key files, so they are validated (`check_label`) before use and passed in
//! `--option=value` form: a crafted key file cannot inject options or reach other paths.

use std::io::Write;
use std::process::{Command, Stdio};

use base64::{Engine, engine::general_purpose::STANDARD};
use vpqc::protect::KeyProvider;
use vpqc_format::protected::check_label;
use zeroize::Zeroizing;

/// AWS KMS encryption context, bound to every wrap and unwrap.
const AWS_CONTEXT: &str = "purpose=vpqc-secret-key";

fn run(program: &str, args: &[String], stdin: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot run {program}: {e}"))?;
    child
        .stdin
        .take()
        .expect("piped")
        .write_all(stdin)
        .map_err(|e| format!("{program}: {e}"))?;
    let out = child
        .wait_with_output()
        .map_err(|e| format!("{program}: {e}"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(format!(
            "{program} failed ({}): {}",
            out.status,
            err.trim().lines().last().unwrap_or("")
        ));
    }
    Ok(Zeroizing::new(out.stdout))
}

fn b64_text(out: &[u8], what: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    let text = std::str::from_utf8(out).map_err(|_| format!("{what}: output is not text"))?;
    STANDARD
        .decode(text.trim())
        .map(Zeroizing::new)
        .map_err(|_| format!("{what}: output is not base64"))
}

/// `MOUNT/KEY` -> (`MOUNT`, `KEY`); the key name is the last path segment.
fn vault_path(label: &str) -> Result<(&str, &str), String> {
    label
        .rsplit_once('/')
        .filter(|(m, k)| !m.is_empty() && !k.is_empty())
        .ok_or_else(|| "vault-transit label must be MOUNT/KEY, e.g. transit/vpqc".to_string())
}

/// Wrap a key-encryption key; returns the bytes to store in the key file.
pub fn wrap(provider: KeyProvider, label: &str, kek: &[u8]) -> Result<Vec<u8>, String> {
    check_label(label).map_err(|e| e.to_string())?;
    let s = |x: &str| x.to_string();
    Ok(match provider {
        KeyProvider::SystemdCreds => run(
            "systemd-creds",
            &[s("encrypt"), format!("--name={label}"), s("-"), s("-")],
            kek,
        )?
        .to_vec(),
        KeyProvider::AwsKms => {
            let out = run(
                "aws",
                &[
                    s("kms"),
                    s("encrypt"),
                    format!("--key-id={label}"),
                    s("--plaintext=fileb:///dev/stdin"),
                    format!("--encryption-context={AWS_CONTEXT}"),
                    s("--query=CiphertextBlob"),
                    s("--output=text"),
                ],
                kek,
            )?;
            b64_text(&out, "aws kms encrypt")?.to_vec()
        }
        KeyProvider::GcpKms => run(
            "gcloud",
            &[
                s("kms"),
                s("encrypt"),
                format!("--key={label}"),
                s("--plaintext-file=-"),
                s("--ciphertext-file=-"),
            ],
            kek,
        )?
        .to_vec(),
        KeyProvider::VaultTransit => {
            let (mount, key) = vault_path(label)?;
            let input = Zeroizing::new(STANDARD.encode(kek));
            let out = run(
                "vault",
                &[
                    s("write"),
                    s("-field=ciphertext"),
                    format!("{mount}/encrypt/{key}"),
                    s("plaintext=-"),
                ],
                input.as_bytes(),
            )?;
            String::from_utf8_lossy(&out).trim().as_bytes().to_vec()
        }
        _ => return Err("unsupported key protection provider".into()),
    })
}

/// Unwrap the key-encryption key of a protected key file.
pub fn unwrap(
    provider: KeyProvider,
    label: &str,
    wrapped: &[u8],
) -> Result<Zeroizing<Vec<u8>>, String> {
    check_label(label).map_err(|e| e.to_string())?;
    let s = |x: &str| x.to_string();
    match provider {
        KeyProvider::SystemdCreds => run(
            "systemd-creds",
            &[s("decrypt"), format!("--name={label}"), s("-"), s("-")],
            wrapped,
        ),
        KeyProvider::AwsKms => {
            let out = run(
                "aws",
                &[
                    s("kms"),
                    s("decrypt"),
                    format!("--key-id={label}"),
                    s("--ciphertext-blob=fileb:///dev/stdin"),
                    format!("--encryption-context={AWS_CONTEXT}"),
                    s("--query=Plaintext"),
                    s("--output=text"),
                ],
                wrapped,
            )?;
            b64_text(&out, "aws kms decrypt")
        }
        KeyProvider::GcpKms => run(
            "gcloud",
            &[
                s("kms"),
                s("decrypt"),
                format!("--key={label}"),
                s("--ciphertext-file=-"),
                s("--plaintext-file=-"),
            ],
            wrapped,
        ),
        KeyProvider::VaultTransit => {
            let (mount, key) = vault_path(label)?;
            let out = run(
                "vault",
                &[
                    s("write"),
                    s("-field=plaintext"),
                    format!("{mount}/decrypt/{key}"),
                    s("ciphertext=-"),
                ],
                wrapped,
            )?;
            b64_text(&out, "vault transit decrypt")
        }
        _ => Err("unsupported key protection provider".into()),
    }
}
