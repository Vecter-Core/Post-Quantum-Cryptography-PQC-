//! Strict DER reading for the few structures x509-parser does not cover (PKCS#8 and the
//! ML-DSA private key CHOICE of RFC 9881).

use crate::{Algorithm, Error, Result};

/// One TLV: `(tag, value, rest)`. Only definite, minimally encoded lengths (DER).
fn tlv(input: &[u8]) -> Result<(u8, &[u8], &[u8])> {
    let bad = Error::Malformed("DER encoding");
    let (&tag, rest) = input.split_first().ok_or(bad.clone())?;
    let (&first, rest) = rest.split_first().ok_or(bad.clone())?;
    let (len, rest) = if first < 0x80 {
        (first as usize, rest)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 || rest.len() < n || rest[0] == 0 {
            return Err(bad); // indefinite, too long, or not minimal
        }
        let len = rest[..n]
            .iter()
            .fold(0usize, |acc, b| (acc << 8) | *b as usize);
        if len < 0x80 {
            return Err(bad); // long form for a short length
        }
        (len, &rest[n..])
    };
    if rest.len() < len {
        return Err(bad);
    }
    Ok((tag, &rest[..len], &rest[len..]))
}

fn expect<'a>(input: &'a [u8], tag: u8, what: &'static str) -> Result<(&'a [u8], &'a [u8])> {
    match tlv(input)? {
        (t, v, rest) if t == tag => Ok((v, rest)),
        _ => Err(Error::Malformed(what)),
    }
}

/// `OneAsymmetricKey` → (algorithm, privateKey OCTET STRING contents).
pub(crate) fn pkcs8(der: &[u8]) -> Result<(Algorithm, Vec<u8>)> {
    let (body, rest) = expect(der, 0x30, "PKCS#8: expected SEQUENCE")?;
    if !rest.is_empty() {
        return Err(Error::Malformed("PKCS#8: trailing data"));
    }
    let (version, body) = expect(body, 0x02, "PKCS#8: expected version")?;
    if version != [0] && version != [1] {
        return Err(Error::Malformed("PKCS#8: unsupported version"));
    }
    let (alg_id, body) = expect(body, 0x30, "PKCS#8: expected AlgorithmIdentifier")?;
    let (oid, params) = expect(alg_id, 0x06, "PKCS#8: expected algorithm OID")?;
    if !params.is_empty() {
        return Err(Error::Malformed(
            "ML-DSA AlgorithmIdentifier must not have parameters",
        ));
    }
    let alg = Algorithm::from_oid_content(oid)?;
    let (private, mut body) = expect(body, 0x04, "PKCS#8: expected privateKey")?;
    // Optional [0] attributes and [1] publicKey (v2) are ignored: the key is derived from the seed.
    while !body.is_empty() {
        let (tag, _, rest) = tlv(body)?;
        if tag != 0xa0 && tag != 0x81 && tag != 0xa1 {
            return Err(Error::Malformed("PKCS#8: unexpected field"));
        }
        body = rest;
    }
    Ok((alg, private.to_vec()))
}

/// `ML-DSA-PrivateKey ::= CHOICE { seed [0] OCTET STRING (SIZE (32)), expandedKey OCTET STRING,
/// both SEQUENCE { seed OCTET STRING (SIZE (32)), expandedKey OCTET STRING } }`
/// → (seed, expanded key if present).
pub(crate) fn ml_dsa_private_key(der: &[u8]) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
    let (tag, value, rest) = tlv(der)?;
    if !rest.is_empty() {
        return Err(Error::Malformed("ML-DSA private key: trailing data"));
    }
    match tag {
        0x80 => Ok((value.to_vec(), None)),
        0x30 => {
            let (seed, value) = expect(value, 0x04, "ML-DSA private key: expected seed")?;
            let (expanded, value) =
                expect(value, 0x04, "ML-DSA private key: expected expandedKey")?;
            if !value.is_empty() {
                return Err(Error::Malformed("ML-DSA private key: trailing data"));
            }
            Ok((seed.to_vec(), Some(expanded.to_vec())))
        }
        0x04 => Err(Error::InvalidKey(
            "expandedKey-only ML-DSA private keys are not supported: export the seed form",
        )),
        _ => Err(Error::Malformed("ML-DSA private key: unknown form")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_lengths() {
        assert!(tlv(&[0x04, 0x01, 0xaa]).is_ok());
        assert!(tlv(&[0x04, 0x81, 0x01, 0xaa]).is_err()); // long form for short length
        assert!(tlv(&[0x04, 0x82, 0x00, 0x80]).is_err()); // leading zero length byte
        assert!(tlv(&[0x04, 0x80]).is_err()); // indefinite
        assert!(tlv(&[0x04, 0x02, 0xaa]).is_err()); // truncated
    }
}
