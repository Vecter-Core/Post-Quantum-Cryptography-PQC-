//! Parsing of PEM/DER certificates and key files. Only algorithm identifiers, sizes and
//! validity dates are extracted; key material is never copied out.

use base64::{Engine, engine::general_purpose::STANDARD};
use x509_parser::prelude::*;
use x509_parser::public_key::PublicKey as ParsedKey;

use crate::model::{Family, Finding, Purpose, Source, classify};

/// Certificates that stay valid after this instant are "long-lived": 2030-01-01T00:00:00Z.
const LONG_LIVED_AFTER: i64 = 1_893_456_000;

fn finding(
    path: &str,
    source: Source,
    algorithm: String,
    family: Family,
    purpose: Purpose,
    detail: String,
    long_lived: bool,
) -> Finding {
    let (risk, tier, advice) = classify(family, purpose, long_lived);
    Finding {
        path: path.to_string(),
        line: None,
        source,
        algorithm,
        family,
        purpose,
        risk,
        tier,
        detail,
        advice,
        long_lived,
    }
}

/// Map an algorithm OID (dotted) plus optional curve OID / RSA size to a family and label.
fn classify_oid(
    oid: &str,
    curve: Option<&str>,
    rsa_bits: Option<usize>,
) -> Option<(Family, Purpose, String)> {
    use Family::*;
    use Purpose::*;
    Some(match oid {
        "1.2.840.113549.1.1.1" | "1.2.840.113549.1.1.10" | "1.2.840.113549.1.1.7" => (
            Rsa,
            KeyExchangeOrSignature,
            match rsa_bits {
                Some(b) => format!("RSA-{b}"),
                None => "RSA".to_string(),
            },
        ),
        "1.2.840.10045.2.1" => {
            let name = match curve {
                Some("1.2.840.10045.3.1.7") => "P-256",
                Some("1.3.132.0.34") => "P-384",
                Some("1.3.132.0.35") => "P-521",
                Some("1.3.132.0.10") => "secp256k1",
                _ => "unknown curve",
            };
            (Ecc, KeyExchangeOrSignature, format!("EC {name}"))
        }
        "1.3.101.112" => (EdDsa, Signature, "Ed25519".into()),
        "1.3.101.113" => (EdDsa, Signature, "Ed448".into()),
        "1.3.101.110" => (X25519, KeyExchange, "X25519".into()),
        "1.3.101.111" => (X25519, KeyExchange, "X448".into()),
        "1.2.840.10040.4.1" => (Dsa, Signature, "DSA".into()),
        "1.2.840.113549.1.3.1" | "1.2.840.10046.2.1" => (Dh, KeyExchange, "Diffie-Hellman".into()),
        // NIST PQC: ML-DSA (17-19), SLH-DSA (20-31), ML-KEM (4.1-4.3).
        o if o.starts_with("2.16.840.1.101.3.4.3.") => {
            let n: u32 = o.rsplit('.').next()?.parse().ok()?;
            match n {
                17 => (PqSignature, Signature, "ML-DSA-44".into()),
                18 => (PqSignature, Signature, "ML-DSA-65".into()),
                19 => (PqSignature, Signature, "ML-DSA-87".into()),
                20..=31 => (PqSignature, Signature, "SLH-DSA".into()),
                _ => return None,
            }
        }
        "2.16.840.1.101.3.4.4.1" => (PqKem, KeyExchange, "ML-KEM-512".into()),
        "2.16.840.1.101.3.4.4.2" => (PqKem, KeyExchange, "ML-KEM-768".into()),
        "2.16.840.1.101.3.4.4.3" => (PqKem, KeyExchange, "ML-KEM-1024".into()),
        _ => return None,
    })
}

fn classify_signature_oid(oid: &str) -> Option<(Family, String)> {
    use Family::*;
    Some(match oid {
        "1.2.840.113549.1.1.5" => (BrokenHash, "sha1WithRSAEncryption".into()),
        "1.2.840.113549.1.1.4" => (BrokenHash, "md5WithRSAEncryption".into()),
        "1.2.840.10045.4.1" => (BrokenHash, "ecdsa-with-SHA1".into()),
        "1.2.840.113549.1.1.11" => (Rsa, "sha256WithRSAEncryption".into()),
        "1.2.840.113549.1.1.12" => (Rsa, "sha384WithRSAEncryption".into()),
        "1.2.840.113549.1.1.13" => (Rsa, "sha512WithRSAEncryption".into()),
        "1.2.840.113549.1.1.10" => (Rsa, "RSASSA-PSS".into()),
        "1.2.840.10045.4.3.2" => (Ecdsa, "ecdsa-with-SHA256".into()),
        "1.2.840.10045.4.3.3" => (Ecdsa, "ecdsa-with-SHA384".into()),
        "1.2.840.10045.4.3.4" => (Ecdsa, "ecdsa-with-SHA512".into()),
        "1.3.101.112" => (EdDsa, "Ed25519".into()),
        "1.3.101.113" => (EdDsa, "Ed448".into()),
        // ML-DSA / SLH-DSA: the signature algorithm OID is the key OID.
        o if o.starts_with("2.16.840.1.101.3.4.3.") => {
            let n: u32 = o.rsplit('.').next()?.parse().ok()?;
            match n {
                17 => (PqSignature, "ML-DSA-44".into()),
                18 => (PqSignature, "ML-DSA-65".into()),
                19 => (PqSignature, "ML-DSA-87".into()),
                20..=31 => (PqSignature, "SLH-DSA".into()),
                _ => (PqSignature, "NIST PQC".into()),
            }
        }
        _ => return None,
    })
}

fn analyse_certificate(path: &str, cert: &X509Certificate<'_>, out: &mut Vec<Finding>) {
    let spki = cert.public_key();
    let oid = spki.algorithm.algorithm.to_id_string();
    let curve = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|p| p.as_oid().ok())
        .map(|o| o.to_id_string());
    let rsa_bits = match spki.parsed() {
        Ok(ParsedKey::RSA(rsa)) => Some(rsa.key_size()),
        _ => None,
    };
    let not_after = cert.validity().not_after.timestamp();
    let long_lived = not_after > LONG_LIVED_AFTER;
    let subject = cert.subject().to_string();
    let expires = cert.validity().not_after.to_string();
    let detail = format!("subject: {subject}; not after: {expires}");

    // A certificate is a signature-bearing object even when its key is RSA/EC: report the
    // public key algorithm with the certificate context, and the signature algorithm separately.
    if let Some((family, _purpose, label)) = classify_oid(&oid, curve.as_deref(), rsa_bits) {
        out.push(finding(
            path,
            Source::Certificate,
            format!("{label} public key"),
            family,
            Purpose::Signature,
            detail.clone(),
            long_lived,
        ));
    } else {
        out.push(finding(
            path,
            Source::Certificate,
            format!("unrecognised key algorithm {oid}"),
            Family::Ecc,
            Purpose::KeyExchangeOrSignature,
            detail.clone(),
            long_lived,
        ));
    }
    let sig_oid = cert.signature_algorithm.algorithm.to_id_string();
    if let Some((family, label)) = classify_signature_oid(&sig_oid) {
        out.push(finding(
            path,
            Source::Certificate,
            format!("{label} signature"),
            family,
            Purpose::Signature,
            detail,
            long_lived,
        ));
    }
}

/// PKCS#8 `PrivateKeyInfo`: read only the AlgorithmIdentifier (and curve parameter).
fn analyse_pkcs8(der: &[u8]) -> Option<(Family, Purpose, String)> {
    use x509_parser::der_parser::ber::BerObjectContent;
    use x509_parser::der_parser::parse_der;
    let (_, obj) = parse_der(der).ok()?;
    let BerObjectContent::Sequence(items) = &obj.content else {
        return None;
    };
    let BerObjectContent::Sequence(alg) = &items.get(1)?.content else {
        return None;
    };
    let oid = match &alg.first()?.content {
        BerObjectContent::OID(o) => o.to_id_string(),
        _ => return None,
    };
    let curve = match alg.get(1).map(|o| &o.content) {
        Some(BerObjectContent::OID(o)) => Some(o.to_id_string()),
        _ => None,
    };
    classify_oid(&oid, curve.as_deref(), None)
}

/// OpenSSH private key: read the public key type string from the blob header.
fn analyse_openssh(blob: &[u8]) -> Option<String> {
    fn take_string<'a>(b: &mut &'a [u8]) -> Option<&'a [u8]> {
        if b.len() < 4 {
            return None;
        }
        let n = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize;
        let rest = &b[4..];
        if rest.len() < n {
            return None;
        }
        let (s, tail) = rest.split_at(n);
        *b = tail;
        Some(s)
    }
    let magic = b"openssh-key-v1\0";
    let mut b = blob.strip_prefix(magic.as_slice())?;
    take_string(&mut b)?; // cipher
    take_string(&mut b)?; // kdf
    take_string(&mut b)?; // kdf options
    if b.len() < 4 {
        return None;
    }
    b = &b[4..]; // number of keys
    let mut public = take_string(&mut b)?;
    let key_type = take_string(&mut public)?;
    String::from_utf8(key_type.to_vec()).ok()
}

fn ssh_type_family(t: &str) -> Option<(Family, Purpose, String)> {
    use Family::*;
    use Purpose::*;
    Some(match t {
        "ssh-rsa" => (Rsa, KeyExchangeOrSignature, "RSA".into()),
        "ssh-ed25519" | "sk-ssh-ed25519@openssh.com" => (EdDsa, Signature, "Ed25519".into()),
        "ssh-dss" => (Dsa, Signature, "DSA".into()),
        t if t.starts_with("ecdsa-sha2-") || t.starts_with("sk-ecdsa-") => {
            (Ecdsa, Signature, "ECDSA".into())
        }
        _ => return None,
    })
}

/// Parse a text file's PEM blocks and, for `.der`/`.cer`/`.crt` binary files, a raw DER
/// certificate. Returns findings; never returns key material.
pub(crate) fn analyse_pem_text(path: &str, text: &str, out: &mut Vec<Finding>) {
    for pem in Pem::iter_from_buffer(text.as_bytes()).flatten() {
        match pem.label.as_str() {
            "CERTIFICATE" | "TRUSTED CERTIFICATE" | "X509 CERTIFICATE" => {
                if let Ok(cert) = pem.parse_x509() {
                    analyse_certificate(path, &cert, out);
                }
            }
            "RSA PRIVATE KEY" => out.push(finding(
                path,
                Source::PrivateKey,
                "RSA private key".into(),
                Family::Rsa,
                Purpose::KeyExchangeOrSignature,
                "PKCS#1 private key stored in a file".into(),
                false,
            )),
            "DSA PRIVATE KEY" => out.push(finding(
                path,
                Source::PrivateKey,
                "DSA private key".into(),
                Family::Dsa,
                Purpose::Signature,
                "private key stored in a file".into(),
                false,
            )),
            "EC PRIVATE KEY" => out.push(finding(
                path,
                Source::PrivateKey,
                "EC private key".into(),
                Family::Ecc,
                Purpose::KeyExchangeOrSignature,
                "SEC1 private key stored in a file".into(),
                false,
            )),
            "PRIVATE KEY" => {
                if let Some((family, purpose, label)) = analyse_pkcs8(&pem.contents) {
                    out.push(finding(
                        path,
                        Source::PrivateKey,
                        format!("{label} private key"),
                        family,
                        purpose,
                        "PKCS#8 private key stored in a file".into(),
                        false,
                    ));
                }
            }
            "OPENSSH PRIVATE KEY" => {
                if let Some((family, purpose, label)) =
                    analyse_openssh(&pem.contents).and_then(|t| ssh_type_family(&t))
                {
                    out.push(finding(
                        path,
                        Source::PrivateKey,
                        format!("{label} private key"),
                        family,
                        purpose,
                        "OpenSSH private key stored in a file".into(),
                        false,
                    ));
                }
            }
            "PUBLIC KEY" => {
                if let Ok((_, spki)) = SubjectPublicKeyInfo::from_der(&pem.contents) {
                    let oid = spki.algorithm.algorithm.to_id_string();
                    let curve = spki
                        .algorithm
                        .parameters
                        .as_ref()
                        .and_then(|p| p.as_oid().ok())
                        .map(|o| o.to_id_string());
                    let bits = match spki.parsed() {
                        Ok(ParsedKey::RSA(r)) => Some(r.key_size()),
                        _ => None,
                    };
                    if let Some((family, purpose, label)) =
                        classify_oid(&oid, curve.as_deref(), bits)
                    {
                        out.push(finding(
                            path,
                            Source::PublicKey,
                            format!("{label} public key"),
                            family,
                            purpose,
                            "SPKI public key".into(),
                            false,
                        ));
                    }
                }
            }
            _ => {}
        }
    }
    // OpenSSH public keys: `ssh-rsa AAAA... comment` lines.
    for (i, line) in text.lines().enumerate() {
        let mut parts = line.split_whitespace();
        if let (Some(t), Some(b64)) = (parts.next(), parts.next())
            && let Some((family, purpose, label)) = ssh_type_family(t)
            && STANDARD.decode(b64).is_ok_and(|d| d.len() > 8)
        {
            let mut f = finding(
                path,
                Source::PublicKey,
                format!("{label} SSH public key"),
                family,
                purpose,
                format!("{t} key"),
                false,
            );
            f.line = Some(i + 1);
            out.push(f);
        }
    }
}

/// Parse a binary DER certificate.
pub(crate) fn analyse_der(path: &str, bytes: &[u8], out: &mut Vec<Finding>) -> bool {
    if let Ok((_, cert)) = X509Certificate::from_der(bytes) {
        analyse_certificate(path, &cert, out);
        true
    } else {
        false
    }
}
