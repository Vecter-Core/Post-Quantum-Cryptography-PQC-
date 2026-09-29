//! Chain verification for ML-DSA certificates.

use std::time::{SystemTime, UNIX_EPOCH};

use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::X509Certificate;
use x509_parser::x509::X509Version;

use crate::cert::{Purpose, oid};
use crate::{Algorithm, Certificate, Error, PublicKey, Result};

/// What [`verify_chain`] checks besides signatures, validity and CA constraints.
#[derive(Clone, Debug)]
pub struct VerifyOptions {
    /// Time of the check (Unix seconds); the system clock if `None`.
    pub now: Option<i64>,
    /// Required DNS name in the leaf's subject alternative names (RFC 6125: the common name is
    /// ignored). Leftmost-label wildcards (`*.example.com`) match exactly one label.
    pub dns_name: Option<String>,
    /// Required extended key usage of the leaf (accepted when the leaf has no EKU extension).
    pub purpose: Option<Purpose>,
    /// Longest accepted path, trust anchor excluded. Default 5.
    pub max_depth: usize,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        VerifyOptions {
            now: None,
            dns_name: None,
            purpose: None,
            max_depth: 5,
        }
    }
}

impl VerifyOptions {
    /// Checks for a TLS server certificate for `dns_name`.
    pub fn for_dns_name(dns_name: &str) -> Self {
        VerifyOptions {
            dns_name: Some(dns_name.to_ascii_lowercase()),
            purpose: Some(Purpose::ServerAuth),
            ..Self::default()
        }
    }
}

const KNOWN_CRITICAL: [&[u8]; 4] = [
    &oid::BASIC_CONSTRAINTS,
    &oid::KEY_USAGE,
    &oid::EXT_KEY_USAGE,
    &oid::SUBJECT_ALT_NAME,
];

struct Info {
    is_ca: bool,
    path_len: Option<u32>,
    key_cert_sign: Option<bool>,
    digital_signature: Option<bool>,
    eku: Option<Vec<Purpose>>,
    dns_names: Vec<String>,
}

/// Structural checks shared by every certificate in the path, and the extensions we use.
fn check(cert: &X509Certificate<'_>, now: i64) -> Result<Info> {
    if cert.version() != X509Version::V3 {
        return Err(Error::InvalidChain("not an X.509 v3 certificate"));
    }
    if cert.signature_algorithm != cert.tbs_certificate.signature {
        return Err(Error::InvalidChain(
            "signature algorithm differs inside the certificate",
        ));
    }
    Algorithm::from_identifier(&cert.signature_algorithm)?;
    let validity = cert.validity();
    if now < validity.not_before.timestamp() {
        return Err(Error::InvalidChain("certificate not yet valid"));
    }
    if now > validity.not_after.timestamp() {
        return Err(Error::InvalidChain("certificate expired"));
    }
    let mut info = Info {
        is_ca: false,
        path_len: None,
        key_cert_sign: None,
        digital_signature: None,
        eku: None,
        dns_names: Vec::new(),
    };
    for ext in cert.extensions() {
        if ext.critical && !KNOWN_CRITICAL.contains(&ext.oid.as_bytes()) {
            return Err(Error::InvalidChain("unsupported critical extension"));
        }
        match ext.parsed_extension() {
            ParsedExtension::BasicConstraints(bc) => {
                info.is_ca = bc.ca;
                info.path_len = bc.path_len_constraint;
            }
            ParsedExtension::KeyUsage(ku) => {
                info.key_cert_sign = Some(ku.key_cert_sign());
                info.digital_signature = Some(ku.digital_signature());
            }
            ParsedExtension::ExtendedKeyUsage(eku) => {
                let mut list = Vec::new();
                if eku.server_auth {
                    list.push(Purpose::ServerAuth);
                }
                if eku.client_auth {
                    list.push(Purpose::ClientAuth);
                }
                if eku.code_signing {
                    list.push(Purpose::CodeSigning);
                }
                info.eku = Some(list);
            }
            ParsedExtension::SubjectAlternativeName(san) => {
                for name in &san.general_names {
                    if let GeneralName::DNSName(n) = name {
                        info.dns_names.push(n.to_ascii_lowercase());
                    }
                }
            }
            ParsedExtension::ParseError { .. } => {
                return Err(Error::InvalidChain("malformed extension"));
            }
            _ => {}
        }
    }
    Ok(info)
}

/// Is `child` signed by `issuer` (names chain and the ML-DSA signature verifies)?
fn issued_by(child: &X509Certificate<'_>, issuer: &X509Certificate<'_>) -> Result<bool> {
    if child.issuer().as_raw() != issuer.subject().as_raw() {
        return Ok(false);
    }
    let key = PublicKey::from_parsed(issuer.public_key())?;
    if Algorithm::from_identifier(&child.signature_algorithm)? != key.algorithm() {
        return Ok(false);
    }
    Ok(key
        .verify(child.tbs_certificate.as_ref(), &child.signature_value.data)
        .is_ok())
}

fn dns_matches(pattern: &str, name: &str) -> bool {
    match pattern.strip_prefix("*.") {
        Some(suffix) => name
            .split_once('.')
            .is_some_and(|(first, rest)| !first.is_empty() && rest == suffix),
        None => pattern == name,
    }
}

/// Verify that `leaf` chains to one of `anchors` through `intermediates`, and return the path
/// (leaf first, anchor last).
///
/// Checks, for every certificate in the path: X.509 v3, ML-DSA-65/87 signature by the next
/// certificate (issuer name equal to the issuer's subject, byte for byte), validity at `now`,
/// and no critical extension other than basic constraints, key usage, extended key usage and
/// subject alternative name. Issuers must be CAs, with `keyCertSign` if they have key usage, and
/// their path length constraints are enforced. The leaf must not be a CA, needs
/// `digitalSignature` if it has key usage, and must match the requested DNS name and purpose.
///
/// Not supported (a chain using them is rejected or unaffected): name constraints and
/// certificate policies (rejected if critical), revocation (CRL, OCSP), non-ML-DSA algorithms.
pub fn verify_chain(
    leaf: &Certificate,
    intermediates: &[Certificate],
    anchors: &[Certificate],
    options: &VerifyOptions,
) -> Result<Vec<Certificate>> {
    let now = options.now.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    });
    let leaf_parsed = leaf.parsed()?;
    let info = check(&leaf_parsed, now)?;
    if info.is_ca {
        return Err(Error::InvalidChain("CA certificate used as an end entity"));
    }
    if info.digital_signature == Some(false) {
        return Err(Error::InvalidChain("leaf key usage lacks digitalSignature"));
    }
    if let (Some(p), Some(eku)) = (options.purpose, &info.eku)
        && !eku.contains(&p)
    {
        return Err(Error::InvalidChain(
            "leaf extended key usage does not allow this purpose",
        ));
    }
    if let Some(name) = &options.dns_name {
        let name = name.to_ascii_lowercase();
        if !info.dns_names.iter().any(|p| dns_matches(p, &name)) {
            return Err(Error::InvalidChain(
                "DNS name not in the leaf's subject alternative names",
            ));
        }
    }

    let inter = intermediates
        .iter()
        .map(Certificate::parsed)
        .collect::<Result<Vec<_>>>()?;
    let roots = anchors
        .iter()
        .map(Certificate::parsed)
        .collect::<Result<Vec<_>>>()?;
    let mut path = vec![leaf.clone()];
    let mut used = vec![false; inter.len()];
    let mut current = leaf_parsed;
    for below in 0..=options.max_depth {
        // `below` = number of intermediate CAs between the candidate issuer and the leaf.
        let ok_issuer = |cand: &X509Certificate<'_>| -> Result<bool> {
            if !issued_by(&current, cand)? {
                return Ok(false);
            }
            let ci = check(cand, now)?;
            if !ci.is_ca {
                return Err(Error::InvalidChain("issuer is not a CA"));
            }
            if ci.key_cert_sign == Some(false) {
                return Err(Error::InvalidChain("issuer key usage lacks keyCertSign"));
            }
            if ci.path_len.is_some_and(|n| (n as usize) < below) {
                return Err(Error::InvalidChain("path length constraint exceeded"));
            }
            Ok(true)
        };
        for (i, root) in roots.iter().enumerate() {
            if ok_issuer(root)? {
                path.push(anchors[i].clone());
                return Ok(path);
            }
        }
        if below == options.max_depth {
            break;
        }
        let mut next = None;
        for (i, cand) in inter.iter().enumerate() {
            if !used[i] && ok_issuer(cand)? {
                next = Some(i);
                break;
            }
        }
        let Some(i) = next else {
            return Err(Error::InvalidChain("no path to a trust anchor"));
        };
        used[i] = true;
        path.push(intermediates[i].clone());
        current = inter[i].clone();
    }
    Err(Error::InvalidChain("path too long"))
}
