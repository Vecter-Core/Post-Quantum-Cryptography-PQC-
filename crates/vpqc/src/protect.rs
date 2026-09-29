//! Secret keys protected at rest (ADR-0013): by a passphrase (Argon2id) or by a key-encryption
//! key that an external system wraps (KMS, HSM, TPM).
//!
//! The protected object encrypts the ordinary secret key encoding with XChaCha20-Poly1305;
//! the header, parameters and nonce are the associated data. A wrong passphrase, a wrong
//! key-encryption key and a modified file all give [`Error::DecryptionFailed`].
//!
//! ```
//! use vpqc::{Profile, encryption, protect};
//!
//! let keys = encryption::generate(Profile::Standard)?;
//! let params = protect::KdfParams { memory_kib: 8 * 1024, ..protect::KdfParams::default() };
//! let stored = protect::protect_with_passphrase(&keys.secret, b"correct horse", params)?;
//! let secret = protect::unprotect_with_passphrase(&stored, b"correct horse")?;
//! assert_eq!(secret.algorithm(), keys.secret.algorithm());
//! # Ok::<(), vpqc::Error>(())
//! ```
//!
//! Running the external system (the `aws`, `gcloud`, `vault` or `systemd-creds` command) is the
//! caller's job, as the `vpqc` CLI does: this module only needs the unwrapped 32-byte key.

use argon2::{Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use vpqc_core::{Error, OsRng, RandomSource, Result, SecretKey};
use vpqc_format::protected::{
    ARGON2_SALT_LEN, PROTECTED_NONCE_LEN, ProtectedSecretKey, check_label,
};
use vpqc_format::{armor, dearmor, decode_secret_key, encode_secret_key};
use zeroize::Zeroizing;

pub use vpqc_format::protected::{KeyProvider, Protection, is_protected_secret_key};

/// Armor label of a protected secret key.
pub const PROTECTED_LABEL: &str = "VPQC PROTECTED SECRET KEY";

/// Length of a key-encryption key.
pub const KEK_LEN: usize = 32;

/// Argon2id cost parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory in KiB (8 MiB to 1 GiB).
    pub memory_kib: u32,
    /// Passes (1 to 16).
    pub iterations: u32,
    /// Lanes (1 to 16).
    pub parallelism: u32,
}

impl Default for KdfParams {
    /// RFC 9106 section 4, second recommended option: 64 MiB, 3 passes, 4 lanes.
    fn default() -> Self {
        KdfParams {
            memory_kib: 64 * 1024,
            iterations: 3,
            parallelism: 4,
        }
    }
}

fn argon2id(passphrase: &[u8], salt: &[u8], p: KdfParams) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(p.memory_kib, p.iterations, p.parallelism, Some(32))
        .map_err(|_| Error::InvalidKey("Argon2id parameters"))?;
    let mut out = Zeroizing::new([0u8; 32]);
    Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase, salt, &mut *out)
        .map_err(|_| Error::InvalidKey("Argon2id"))?;
    Ok(out)
}

fn seal(key: &SecretKey, kek: &[u8; KEK_LEN], protection: Protection) -> Result<Vec<u8>> {
    let mut nonce = [0u8; PROTECTED_NONCE_LEN];
    OsRng.fill(&mut nonce)?;
    let mut object = ProtectedSecretKey {
        protection,
        nonce,
        ciphertext: Vec::new(),
    };
    let plaintext = Zeroizing::new(encode_secret_key(key));
    object.ciphertext = XChaCha20Poly1305::new(kek.into())
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &plaintext,
                aad: &object.header(),
            },
        )
        .map_err(|_| Error::Backend("XChaCha20-Poly1305"))?;
    object.encode()
}

fn open(object: &ProtectedSecretKey, kek: &[u8; KEK_LEN]) -> Result<SecretKey> {
    let plaintext = Zeroizing::new(
        XChaCha20Poly1305::new(kek.into())
            .decrypt(
                &XNonce::from(object.nonce),
                Payload {
                    msg: &object.ciphertext,
                    aad: &object.header(),
                },
            )
            .map_err(|_| Error::DecryptionFailed)?,
    );
    decode_secret_key(&plaintext)
}

/// Encrypt a secret key under a passphrase (Argon2id with `params`, random salt and nonce).
/// Returns the binary protected key; see [`to_text`] for the armored form.
pub fn protect_with_passphrase(
    key: &SecretKey,
    passphrase: &[u8],
    params: KdfParams,
) -> Result<Vec<u8>> {
    if passphrase.is_empty() {
        return Err(Error::InvalidKey("empty passphrase"));
    }
    let mut salt = [0u8; ARGON2_SALT_LEN];
    OsRng.fill(&mut salt)?;
    let protection = Protection::Passphrase {
        memory_kib: params.memory_kib,
        iterations: params.iterations,
        parallelism: params.parallelism,
        salt,
    };
    // Check the ranges before spending time on Argon2.
    ProtectedSecretKey {
        protection: protection.clone(),
        nonce: [0; PROTECTED_NONCE_LEN],
        ciphertext: vec![0; 16],
    }
    .encode()?;
    let kek = argon2id(passphrase, &salt, params)?;
    seal(key, &kek, protection)
}

/// Decrypt a passphrase-protected key (binary or armored).
pub fn unprotect_with_passphrase(bytes: &[u8], passphrase: &[u8]) -> Result<SecretKey> {
    let object = parse(bytes)?;
    let Protection::Passphrase {
        memory_kib,
        iterations,
        parallelism,
        salt,
    } = &object.protection
    else {
        return Err(Error::InvalidKey("key is not passphrase-protected"));
    };
    let params = KdfParams {
        memory_kib: *memory_kib,
        iterations: *iterations,
        parallelism: *parallelism,
    };
    open(&object, &*argon2id(passphrase, salt, params)?)
}

/// A fresh random key-encryption key, to be wrapped by an external system and then passed to
/// [`protect_with_kek`].
pub fn generate_kek() -> Result<Zeroizing<[u8; KEK_LEN]>> {
    let mut kek = Zeroizing::new([0u8; KEK_LEN]);
    OsRng.fill(&mut *kek)?;
    Ok(kek)
}

/// Encrypt a secret key under `kek`, recording which external system wrapped it (`provider`,
/// `label`) and the wrapped form it returned. The unwrapped `kek` is not stored.
pub fn protect_with_kek(
    key: &SecretKey,
    kek: &[u8; KEK_LEN],
    provider: KeyProvider,
    label: &str,
    wrapped: &[u8],
) -> Result<Vec<u8>> {
    check_label(label)?;
    seal(
        key,
        kek,
        Protection::External {
            provider,
            label: label.to_owned(),
            wrapped: wrapped.to_vec(),
        },
    )
}

/// Decrypt an externally protected key with the key-encryption key its provider unwrapped.
pub fn unprotect_with_kek(bytes: &[u8], kek: &[u8]) -> Result<SecretKey> {
    let object = parse(bytes)?;
    if !matches!(object.protection, Protection::External { .. }) {
        return Err(Error::InvalidKey("key is not externally protected"));
    }
    let kek: &[u8; KEK_LEN] = kek.try_into().map_err(|_| Error::DecryptionFailed)?;
    open(&object, kek)
}

/// How a protected key (binary or armored) is protected, without decrypting it.
pub fn protection(bytes: &[u8]) -> Result<Protection> {
    Ok(parse(bytes)?.protection)
}

/// Armored text form of a binary protected key.
pub fn to_text(protected: &[u8]) -> String {
    armor(PROTECTED_LABEL, protected)
}

fn parse(bytes: &[u8]) -> Result<ProtectedSecretKey> {
    match std::str::from_utf8(bytes) {
        Ok(text) if text.trim_start().starts_with("-----BEGIN") => {
            ProtectedSecretKey::decode(&dearmor(PROTECTED_LABEL, text)?)
        }
        _ => ProtectedSecretKey::decode(bytes),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Profile, encryption, signing};

    const FAST: KdfParams = KdfParams {
        memory_kib: 8 * 1024,
        iterations: 1,
        parallelism: 1,
    };

    #[test]
    fn passphrase_round_trip_and_failures() {
        let keys = signing::generate(Profile::Standard).unwrap();
        let stored = protect_with_passphrase(&keys.secret, "mật khẩu".as_bytes(), FAST).unwrap();
        let back = unprotect_with_passphrase(&stored, "mật khẩu".as_bytes()).unwrap();
        assert_eq!(back.expose_bytes(), keys.secret.expose_bytes());
        // The armored form works too.
        let text = to_text(&stored);
        assert!(text.starts_with("-----BEGIN VPQC PROTECTED SECRET KEY-----"));
        unprotect_with_passphrase(text.as_bytes(), "mật khẩu".as_bytes()).unwrap();
        assert_eq!(
            unprotect_with_passphrase(&stored, b"mat khau").unwrap_err(),
            Error::DecryptionFailed
        );
        assert!(protect_with_passphrase(&keys.secret, b"", FAST).is_err());
        assert!(
            protect_with_passphrase(
                &keys.secret,
                b"x",
                KdfParams {
                    memory_kib: 1024,
                    ..FAST
                }
            )
            .is_err()
        );
        // Every byte is authenticated: header, parameters, nonce and ciphertext. (A change in
        // the cost parameters changes the derived key, so it fails the same way.)
        for i in 0..stored.len() {
            let mut bad = stored.clone();
            bad[i] ^= 0x01;
            assert!(
                unprotect_with_passphrase(&bad, "mật khẩu".as_bytes()).is_err(),
                "byte {i}"
            );
        }
        assert!(unprotect_with_kek(&stored, &[0; 32]).is_err());
    }

    #[test]
    fn kek_round_trip_and_failures() {
        let keys = encryption::generate(Profile::Cnsa2).unwrap();
        let kek = generate_kek().unwrap();
        let stored = protect_with_kek(
            &keys.secret,
            &kek,
            KeyProvider::AwsKms,
            "alias/vpqc",
            b"blob",
        )
        .unwrap();
        assert_eq!(
            protection(&stored).unwrap(),
            Protection::External {
                provider: KeyProvider::AwsKms,
                label: "alias/vpqc".into(),
                wrapped: b"blob".to_vec()
            }
        );
        let back = unprotect_with_kek(&stored, &*kek).unwrap();
        assert_eq!(back.expose_bytes(), keys.secret.expose_bytes());
        assert_eq!(
            unprotect_with_kek(&stored, &[0; 32]).unwrap_err(),
            Error::DecryptionFailed
        );
        assert!(unprotect_with_kek(&stored, &[0; 31]).is_err());
        assert!(unprotect_with_passphrase(&stored, b"x").is_err());
        assert!(
            protect_with_kek(
                &keys.secret,
                &kek,
                KeyProvider::VaultTransit,
                "../sys",
                b"b"
            )
            .is_err()
        );
        // Swapping the wrapped blob (e.g. to one wrapped under another KMS key) is detected.
        let mut other = ProtectedSecretKey::decode(&stored).unwrap();
        other.protection = Protection::External {
            provider: KeyProvider::AwsKms,
            label: "alias/vpqc".into(),
            wrapped: b"blob2".to_vec(),
        };
        assert_eq!(
            unprotect_with_kek(&other.encode().unwrap(), &*kek).unwrap_err(),
            Error::DecryptionFailed
        );
    }
}
