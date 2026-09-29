//! PEM (RFC 7468) with a strict label check.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use crate::{Error, Result};

pub(crate) fn encode(label: &str, der: &[u8]) -> String {
    let b64 = STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// Every block with `label`, in order.
pub(crate) fn decode_all(label: &str, text: &str) -> Result<Vec<Vec<u8>>> {
    let (begin, end) = (
        format!("-----BEGIN {label}-----"),
        format!("-----END {label}-----"),
    );
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find(&begin) {
        let after = &rest[start + begin.len()..];
        let stop = after
            .find(&end)
            .ok_or(Error::Malformed("PEM: missing END line"))?;
        let body: String = after[..stop].split_whitespace().collect();
        out.push(
            STANDARD
                .decode(body)
                .map_err(|_| Error::Malformed("PEM: bad base64"))?,
        );
        rest = &after[stop + end.len()..];
    }
    Ok(out)
}

pub(crate) fn decode(label: &str, text: &str) -> Result<Vec<u8>> {
    let mut blocks = decode_all(label, text)?;
    match blocks.len() {
        1 => Ok(blocks.remove(0)),
        0 => Err(Error::Malformed("PEM: no block with the expected label")),
        _ => Err(Error::Malformed("PEM: more than one block")),
    }
}
