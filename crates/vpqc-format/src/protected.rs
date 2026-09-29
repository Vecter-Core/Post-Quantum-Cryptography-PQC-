//! Protected (encrypted) secret keys, ADR-0013.
//!
//! ```text
//! protected : "VPQC" 01 07 method:u8 params_len:u16 params | nonce:24 | ciphertext
//!   method 1, passphrase : memory_kib:u32 iterations:u32 parallelism:u32 salt:16   (Argon2id)
//!   method 2, external   : provider:u8 label_len:u16 label wrapped_len:u16 wrapped  (KMS/HSM/TPM)
//! ```
//! `ciphertext` is XChaCha20-Poly1305 over the ordinary secret key object (kind 4), with every
//! byte before it (header, parameters and nonce) as associated data, so the parameters cannot
//! be changed without detection. This module only encodes and parses; the cryptography is in
//! the `vpqc` crate.

use vpqc_core::{Error, Result};

use crate::{MAGIC, Reader, VERSION, kind};

/// Argon2id salt length.
pub const ARGON2_SALT_LEN: usize = 16;
/// XChaCha20-Poly1305 nonce length.
pub const PROTECTED_NONCE_LEN: usize = 24;

/// Accepted Argon2id parameter ranges when parsing. The upper bounds stop a crafted file from
/// making the reader allocate or compute without limit (1 GiB, 16 passes, 16 lanes); the lower
/// bounds reject parameters too weak to be worth a passphrase.
pub const ARGON2_MEMORY_KIB: std::ops::RangeInclusive<u32> = 8 * 1024..=1024 * 1024;
/// See [`ARGON2_MEMORY_KIB`].
pub const ARGON2_ITERATIONS: std::ops::RangeInclusive<u32> = 1..=16;
/// See [`ARGON2_MEMORY_KIB`].
pub const ARGON2_PARALLELISM: std::ops::RangeInclusive<u32> = 1..=16;

const METHOD_PASSPHRASE: u8 = 1;
const METHOD_EXTERNAL: u8 = 2;
const MAX_LABEL: usize = 256;
const MAX_WRAPPED: usize = 8192;
const MAX_CIPHERTEXT: usize = 4096;

/// The system that wraps the key-encryption key of an externally protected key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KeyProvider {
    /// `systemd-creds` (TPM2 and/or the host credential key).
    SystemdCreds,
    /// AWS KMS (symmetric key), through the `aws` CLI.
    AwsKms,
    /// Google Cloud KMS (symmetric key), through the `gcloud` CLI.
    GcpKms,
    /// HashiCorp Vault / OpenBao Transit, through the `vault` CLI.
    VaultTransit,
}

impl KeyProvider {
    /// Wire identifier.
    pub const fn id(self) -> u8 {
        match self {
            KeyProvider::SystemdCreds => 1,
            KeyProvider::AwsKms => 2,
            KeyProvider::GcpKms => 3,
            KeyProvider::VaultTransit => 4,
        }
    }

    /// The provider with this wire identifier.
    pub fn from_id(id: u8) -> Result<Self> {
        Ok(match id {
            1 => KeyProvider::SystemdCreds,
            2 => KeyProvider::AwsKms,
            3 => KeyProvider::GcpKms,
            4 => KeyProvider::VaultTransit,
            _ => return Err(Error::Unsupported("key protection provider")),
        })
    }

    /// Name used on the command line.
    pub const fn name(self) -> &'static str {
        match self {
            KeyProvider::SystemdCreds => "systemd-creds",
            KeyProvider::AwsKms => "aws-kms",
            KeyProvider::GcpKms => "gcp-kms",
            KeyProvider::VaultTransit => "vault-transit",
        }
    }

    /// Parse a command-line name.
    pub fn from_name(name: &str) -> Result<Self> {
        [
            KeyProvider::SystemdCreds,
            KeyProvider::AwsKms,
            KeyProvider::GcpKms,
            KeyProvider::VaultTransit,
        ]
        .into_iter()
        .find(|p| p.name() == name)
        .ok_or(Error::Unsupported("key protection provider"))
    }
}

/// A provider key label (key id, ARN, resource name, credential name...). Only
/// `A-Z a-z 0-9 . _ : / -`, 1 to 256 characters, not starting with `-`, without `..`:
/// labels read from a key file end up as command arguments, so they must not be able to act as
/// options or walk to other paths (e.g. other Vault endpoints).
pub fn check_label(label: &str) -> Result<()> {
    let ok = !label.is_empty()
        && label.len() <= MAX_LABEL
        && !label.starts_with('-')
        && !label.contains("..")
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:/-".contains(&b));
    if ok {
        Ok(())
    } else {
        Err(Error::Format("invalid key provider label"))
    }
}

/// How the key is protected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Protection {
    /// A passphrase stretched with Argon2id (RFC 9106).
    Passphrase {
        /// Memory in KiB.
        memory_kib: u32,
        /// Passes.
        iterations: u32,
        /// Lanes.
        parallelism: u32,
        /// Random salt.
        salt: [u8; ARGON2_SALT_LEN],
    },
    /// A random key-encryption key wrapped by an external system.
    External {
        /// The wrapping system.
        provider: KeyProvider,
        /// Which key in that system (see [`check_label`]).
        label: String,
        /// The wrapped key-encryption key, as the provider returned it.
        wrapped: Vec<u8>,
    },
}

/// A parsed protected secret key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtectedSecretKey {
    /// How the key is protected.
    pub protection: Protection,
    /// XChaCha20-Poly1305 nonce.
    pub nonce: [u8; PROTECTED_NONCE_LEN],
    /// The encrypted secret key object (with the 16-byte tag).
    pub ciphertext: Vec<u8>,
}

impl ProtectedSecretKey {
    /// Everything before the ciphertext: the associated data of the encryption.
    pub fn header(&self) -> Vec<u8> {
        let mut params = Vec::new();
        let method = match &self.protection {
            Protection::Passphrase {
                memory_kib,
                iterations,
                parallelism,
                salt,
            } => {
                params.extend_from_slice(&memory_kib.to_be_bytes());
                params.extend_from_slice(&iterations.to_be_bytes());
                params.extend_from_slice(&parallelism.to_be_bytes());
                params.extend_from_slice(salt);
                METHOD_PASSPHRASE
            }
            Protection::External {
                provider,
                label,
                wrapped,
            } => {
                params.push(provider.id());
                params.extend_from_slice(&(label.len() as u16).to_be_bytes());
                params.extend_from_slice(label.as_bytes());
                params.extend_from_slice(&(wrapped.len() as u16).to_be_bytes());
                params.extend_from_slice(wrapped);
                METHOD_EXTERNAL
            }
        };
        let mut out = Vec::with_capacity(9 + params.len() + PROTECTED_NONCE_LEN);
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.push(kind::PROTECTED_SECRET_KEY);
        out.push(method);
        out.extend_from_slice(&(params.len() as u16).to_be_bytes());
        out.extend_from_slice(&params);
        out.extend_from_slice(&self.nonce);
        out
    }

    /// Serialize. Fails if the fields are out of the ranges [`decode`](Self::decode) accepts.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut out = self.header();
        out.extend_from_slice(&self.ciphertext);
        Ok(out)
    }

    fn validate(&self) -> Result<()> {
        match &self.protection {
            Protection::Passphrase {
                memory_kib,
                iterations,
                parallelism,
                ..
            } => {
                if !ARGON2_MEMORY_KIB.contains(memory_kib)
                    || !ARGON2_ITERATIONS.contains(iterations)
                    || !ARGON2_PARALLELISM.contains(parallelism)
                {
                    return Err(Error::Format("Argon2id parameters out of range"));
                }
            }
            Protection::External { label, wrapped, .. } => {
                check_label(label)?;
                if wrapped.is_empty() || wrapped.len() > MAX_WRAPPED {
                    return Err(Error::Format("wrapped key length"));
                }
            }
        }
        if !(16..=MAX_CIPHERTEXT).contains(&self.ciphertext.len()) {
            return Err(Error::Format("protected key ciphertext length"));
        }
        Ok(())
    }

    /// Parse (strictly: no trailing bytes, parameters in range).
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        r.header(kind::PROTECTED_SECRET_KEY)?;
        let method = r.u8()?;
        let params_len = r.u16()? as usize;
        let mut p = Reader::new(r.take(params_len)?);
        let protection = match method {
            METHOD_PASSPHRASE => {
                let memory_kib = p.u32()?;
                let iterations = p.u32()?;
                let parallelism = p.u32()?;
                let salt = p.take(ARGON2_SALT_LEN)?.try_into().expect("16 bytes");
                Protection::Passphrase {
                    memory_kib,
                    iterations,
                    parallelism,
                    salt,
                }
            }
            METHOD_EXTERNAL => {
                let provider = KeyProvider::from_id(p.u8()?)?;
                let len = p.u16()? as usize;
                let label = std::str::from_utf8(p.take(len)?)
                    .map_err(|_| Error::Format("invalid key provider label"))?
                    .to_owned();
                let len = p.u16()? as usize;
                let wrapped = p.take(len)?.to_vec();
                Protection::External {
                    provider,
                    label,
                    wrapped,
                }
            }
            _ => return Err(Error::Unsupported("key protection method")),
        };
        if !p.is_empty() {
            return Err(Error::Format("trailing bytes in protection parameters"));
        }
        let nonce = r.take(PROTECTED_NONCE_LEN)?.try_into().expect("24 bytes");
        let key = ProtectedSecretKey {
            protection,
            nonce,
            ciphertext: r.rest().to_vec(),
        };
        key.validate()?;
        Ok(key)
    }
}

/// Does `bytes` look like a protected secret key (magic and kind; not a full parse)?
pub fn is_protected_secret_key(bytes: &[u8]) -> bool {
    bytes.len() > 6 && bytes[..4] == MAGIC && bytes[5] == kind::PROTECTED_SECRET_KEY
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(protection: Protection) -> ProtectedSecretKey {
        ProtectedSecretKey {
            protection,
            nonce: [7; 24],
            ciphertext: vec![9; 60],
        }
    }

    #[test]
    fn round_trip_and_strictness() {
        let pass = sample(Protection::Passphrase {
            memory_kib: 65536,
            iterations: 3,
            parallelism: 4,
            salt: [1; 16],
        });
        let ext = sample(Protection::External {
            provider: KeyProvider::AwsKms,
            label: "arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
                .into(),
            wrapped: vec![3; 184],
        });
        for key in [pass, ext] {
            let bytes = key.encode().unwrap();
            assert!(is_protected_secret_key(&bytes));
            assert_eq!(ProtectedSecretKey::decode(&bytes).unwrap(), key);
            assert_eq!(key.header().len(), bytes.len() - key.ciphertext.len());
            for n in 0..key.header().len() + 16 {
                assert!(
                    ProtectedSecretKey::decode(&bytes[..n]).is_err(),
                    "prefix {n}"
                );
            }
        }
        // Out-of-range Argon2 parameters, both when writing and when reading.
        for (m, t, p) in [
            (1024, 3, 4),
            (2 << 20, 3, 4),
            (65536, 0, 4),
            (65536, 17, 4),
            (65536, 3, 0),
        ] {
            let k = sample(Protection::Passphrase {
                memory_kib: m,
                iterations: t,
                parallelism: p,
                salt: [0; 16],
            });
            assert!(k.encode().is_err());
            let mut raw = k.header();
            raw.extend_from_slice(&k.ciphertext);
            assert!(ProtectedSecretKey::decode(&raw).is_err());
        }
    }

    #[test]
    fn labels() {
        for ok in [
            "alias/vpqc",
            "projects/p/locations/global/keyRings/r/cryptoKeys/k",
            "transit/vpqc-keys",
            "vpqc.secret_key",
        ] {
            check_label(ok).unwrap();
        }
        for bad in [
            "",
            "-oProxyCommand=x",
            "--endpoint-url=http://evil",
            "transit/../sys/policy/x",
            "a b",
            "a;b",
            "a$b",
            "a=b",
            "a@b",
            "a\nb",
            &"x".repeat(257),
        ] {
            assert!(check_label(bad).is_err(), "{bad}");
        }
        assert_eq!(KeyProvider::from_name("vault-transit").unwrap().id(), 4);
        assert!(KeyProvider::from_id(9).is_err());
    }
}
