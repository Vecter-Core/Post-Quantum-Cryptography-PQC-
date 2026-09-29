use base64::{Engine, engine::general_purpose::STANDARD};
use vpqc_core::{Error, Result};

/// Encode `bytes` as text: `-----BEGIN <label>-----`, base64 in 64-column lines, `-----END <label>-----`.
pub fn armor(label: &str, bytes: &[u8]) -> String {
    let b64 = STANDARD.encode(bytes);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// Decode armored text produced by [`armor`], requiring the given `label`.
/// Whitespace inside the body is ignored; text outside the markers is rejected.
pub fn dearmor(label: &str, text: &str) -> Result<Vec<u8>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let text = text.trim();
    let body = text
        .strip_prefix(&begin)
        .and_then(|t| t.strip_suffix(&end))
        .ok_or(Error::Format("missing armor markers"))?;
    let body: String = body.split_whitespace().collect();
    STANDARD
        .decode(body.as_bytes())
        .map_err(|_| Error::Format("invalid base64"))
}
