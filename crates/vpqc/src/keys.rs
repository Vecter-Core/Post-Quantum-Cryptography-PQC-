//! Key serialization: binary and armored text.

use vpqc_core::{PublicKey, Result, SecretKey};
use vpqc_format::{
    armor, dearmor, decode_public_key, decode_secret_key, encode_public_key, encode_secret_key,
};

const PUBLIC_LABEL: &str = "VPQC PUBLIC KEY";
const SECRET_LABEL: &str = "VPQC SECRET KEY";

/// Binary encoding of a public key.
pub fn public_to_bytes(key: &PublicKey) -> Vec<u8> {
    encode_public_key(key)
}

/// Parse a binary public key.
pub fn public_from_bytes(bytes: &[u8]) -> Result<PublicKey> {
    decode_public_key(bytes)
}

/// Armored text encoding of a public key.
pub fn public_to_text(key: &PublicKey) -> String {
    armor(PUBLIC_LABEL, &encode_public_key(key))
}

/// Parse an armored public key.
pub fn public_from_text(text: &str) -> Result<PublicKey> {
    decode_public_key(&dearmor(PUBLIC_LABEL, text)?)
}

/// Binary encoding of a secret key. **Unencrypted**; protect the output.
pub fn secret_to_bytes(key: &SecretKey) -> Vec<u8> {
    encode_secret_key(key)
}

/// Parse a binary secret key.
pub fn secret_from_bytes(bytes: &[u8]) -> Result<SecretKey> {
    decode_secret_key(bytes)
}

/// Armored text encoding of a secret key. **Unencrypted**; protect the output.
pub fn secret_to_text(key: &SecretKey) -> String {
    armor(SECRET_LABEL, &encode_secret_key(key))
}

/// Parse an armored secret key.
pub fn secret_from_text(text: &str) -> Result<SecretKey> {
    decode_secret_key(&dearmor(SECRET_LABEL, text)?)
}
