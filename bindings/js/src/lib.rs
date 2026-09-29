//! WebAssembly bindings. Thin wrappers: all logic is in the `vpqc` Rust crates.
//!
//! Profiles: "standard", "fast-auth", "cnsa2", "high".
//!
//! Errors are thrown as `Error` objects with `name = "VpqcError"` and a stable `code`
//! string (`DECRYPTION_FAILED`, `VERIFICATION_FAILED`, `INVALID_INPUT`, `BACKEND`).

use js_sys::Reflect;
use vpqc::{Error, Profile, encryption, keys, signing};
use wasm_bindgen::prelude::*;

fn fail(e: Error) -> JsValue {
    let code = match e {
        Error::DecryptionFailed => "DECRYPTION_FAILED",
        Error::VerificationFailed => "VERIFICATION_FAILED",
        Error::Rng | Error::Backend(_) => "BACKEND",
        _ => "INVALID_INPUT",
    };
    let err = js_sys::Error::new(&e.to_string());
    err.set_name("VpqcError");
    // Setting a plain property cannot fail on a fresh Error object.
    let _ = Reflect::set(&err, &JsValue::from_str("code"), &JsValue::from_str(code));
    err.into()
}

fn profile(name: &str) -> Result<Profile, JsValue> {
    Profile::from_name(name).map_err(fail)
}

/// A generated key pair (binary-encoded keys).
#[wasm_bindgen]
pub struct KeyPair {
    public: Vec<u8>,
    secret: Vec<u8>,
}

#[wasm_bindgen]
impl KeyPair {
    /// Public key, safe to share.
    #[wasm_bindgen(getter, js_name = publicKey)]
    pub fn public_key(&self) -> Vec<u8> {
        self.public.clone()
    }

    /// Secret key. Keep private. JavaScript cannot guarantee zeroization.
    #[wasm_bindgen(getter, js_name = secretKey)]
    pub fn secret_key(&self) -> Vec<u8> {
        self.secret.clone()
    }
}

/// Generate an encryption key pair. `profile`: "standard" | "fast-auth" | "cnsa2" | "high".
#[wasm_bindgen(js_name = generateEncryptionKeypair)]
pub fn generate_encryption_keypair(profile_name: Option<String>) -> Result<KeyPair, JsValue> {
    let p = profile(profile_name.as_deref().unwrap_or("standard"))?;
    let pair = encryption::generate(p).map_err(fail)?;
    Ok(KeyPair {
        public: keys::public_to_bytes(&pair.public),
        secret: keys::secret_to_bytes(&pair.secret),
    })
}

/// Generate a signing key pair. `profile`: "standard" | "fast-auth" | "cnsa2" | "high".
#[wasm_bindgen(js_name = generateSigningKeypair)]
pub fn generate_signing_keypair(profile_name: Option<String>) -> Result<KeyPair, JsValue> {
    let p = profile(profile_name.as_deref().unwrap_or("standard"))?;
    let pair = signing::generate(p).map_err(fail)?;
    Ok(KeyPair {
        public: keys::public_to_bytes(&pair.public),
        secret: keys::secret_to_bytes(&pair.secret),
    })
}

/// Encrypt `plaintext` to `publicKey`; `aad` is authenticated context.
#[wasm_bindgen]
pub fn seal(public_key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, JsValue> {
    let pk = keys::public_from_bytes(public_key).map_err(fail)?;
    encryption::seal(&pk, plaintext, aad).map_err(fail)
}

/// Decrypt a sealed message. Throws `DECRYPTION_FAILED` on any mismatch.
#[wasm_bindgen]
pub fn unseal(secret_key: &[u8], sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>, JsValue> {
    let sk = keys::secret_from_bytes(secret_key).map_err(fail)?;
    encryption::open(&sk, sealed, aad).map_err(fail)
}

/// Sign `message` under `context` (at most 255 bytes).
#[wasm_bindgen]
pub fn sign(secret_key: &[u8], message: &[u8], context: &[u8]) -> Result<Vec<u8>, JsValue> {
    let sk = keys::secret_from_bytes(secret_key).map_err(fail)?;
    signing::sign(&sk, message, context).map_err(fail)
}

/// Verify a detached signature. Throws `VERIFICATION_FAILED` if invalid.
#[wasm_bindgen]
pub fn verify(
    public_key: &[u8],
    message: &[u8],
    context: &[u8],
    signature: &[u8],
) -> Result<(), JsValue> {
    let pk = keys::public_from_bytes(public_key).map_err(fail)?;
    signing::verify(&pk, message, context, signature).map_err(fail)
}

/// Armored text encoding of a public key.
#[wasm_bindgen(js_name = publicKeyToText)]
pub fn public_key_to_text(public_key: &[u8]) -> Result<String, JsValue> {
    Ok(keys::public_to_text(
        &keys::public_from_bytes(public_key).map_err(fail)?,
    ))
}

/// Parse an armored public key into its binary encoding.
#[wasm_bindgen(js_name = publicKeyFromText)]
pub fn public_key_from_text(text: &str) -> Result<Vec<u8>, JsValue> {
    Ok(keys::public_to_bytes(
        &keys::public_from_text(text).map_err(fail)?,
    ))
}

/// Armored text encoding of a secret key. Unencrypted.
#[wasm_bindgen(js_name = secretKeyToText)]
pub fn secret_key_to_text(secret_key: &[u8]) -> Result<String, JsValue> {
    Ok(keys::secret_to_text(
        &keys::secret_from_bytes(secret_key).map_err(fail)?,
    ))
}

/// Parse an armored secret key into its binary encoding.
#[wasm_bindgen(js_name = secretKeyFromText)]
pub fn secret_key_from_text(text: &str) -> Result<Vec<u8>, JsValue> {
    Ok(keys::secret_to_bytes(
        &keys::secret_from_text(text).map_err(fail)?,
    ))
}

fn fail_io(e: std::io::Error) -> JsValue {
    match vpqc::stream::crypto_error(&e) {
        Some(c) => fail(c.clone()),
        None => fail(Error::Backend("I/O error")),
    }
}

fn finished() -> JsValue {
    fail(Error::Format("stream already finished"))
}

/// Incremental stream encryption (ADR-0007) for data of any size, e.g. a browser `File`
/// read through `file.stream()`. Concatenate every returned piece in order.
#[wasm_bindgen]
pub struct StreamEncryptor {
    inner: Option<vpqc::stream::Encryptor<Vec<u8>>>,
}

#[wasm_bindgen]
impl StreamEncryptor {
    /// Start a stream to `publicKey`; `aad` is authenticated context.
    #[wasm_bindgen(constructor)]
    pub fn new(public_key: &[u8], aad: &[u8]) -> Result<StreamEncryptor, JsValue> {
        let pk = keys::public_from_bytes(public_key).map_err(fail)?;
        let enc = vpqc::stream::Encryptor::new(&pk, aad, Vec::new()).map_err(fail_io)?;
        Ok(StreamEncryptor { inner: Some(enc) })
    }

    /// Add plaintext; returns the ciphertext produced so far (the first call includes the header).
    pub fn push(&mut self, data: &[u8]) -> Result<Vec<u8>, JsValue> {
        use std::io::Write;
        let enc = self.inner.as_mut().ok_or_else(finished)?;
        enc.write_all(data).map_err(fail_io)?;
        Ok(std::mem::take(enc.get_mut()))
    }

    /// Write the final chunk; returns the remaining ciphertext.
    pub fn finish(&mut self) -> Result<Vec<u8>, JsValue> {
        self.inner
            .take()
            .ok_or_else(finished)?
            .finish()
            .map_err(fail_io)
    }
}

/// Incremental stream decryption. Plaintext returned by `push` must be discarded if a later
/// `push` or `finish` throws; only a successful `finish` proves the stream is complete.
#[wasm_bindgen]
pub struct StreamDecryptor {
    inner: Option<vpqc::stream::PushDecryptor>,
}

#[wasm_bindgen]
impl StreamDecryptor {
    /// Prepare to decrypt a stream for `secretKey` with context `aad`.
    #[wasm_bindgen(constructor)]
    pub fn new(secret_key: &[u8], aad: &[u8]) -> Result<StreamDecryptor, JsValue> {
        let sk = keys::secret_from_bytes(secret_key).map_err(fail)?;
        Ok(StreamDecryptor {
            inner: Some(vpqc::stream::PushDecryptor::new(&sk, aad)),
        })
    }

    /// Add ciphertext; returns plaintext of the chunks that are complete.
    pub fn push(&mut self, data: &[u8]) -> Result<Vec<u8>, JsValue> {
        self.inner
            .as_mut()
            .ok_or_else(finished)?
            .update(data)
            .map_err(fail_io)
    }

    /// Verify the final chunk and return its plaintext. Throws `DECRYPTION_FAILED` for a
    /// truncated or modified stream.
    pub fn finish(&mut self) -> Result<Vec<u8>, JsValue> {
        self.inner
            .take()
            .ok_or_else(finished)?
            .finish()
            .map_err(fail_io)
    }
}

/// Native library version.
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
