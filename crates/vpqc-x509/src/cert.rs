//! Certificate creation.

use std::time::{SystemTime, UNIX_EPOCH};

use x509_parser::extensions::ParsedExtension;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::der::{self, seq};
use crate::{Error, PrivateKey, PublicKey, Result, pem};

pub(crate) mod oid {
    pub const COMMON_NAME: [u8; 3] = [0x55, 0x04, 0x03];
    pub const ORGANIZATION: [u8; 3] = [0x55, 0x04, 0x0a];
    pub const SUBJECT_KEY_ID: [u8; 3] = [0x55, 0x1d, 0x0e];
    pub const KEY_USAGE: [u8; 3] = [0x55, 0x1d, 0x0f];
    pub const SUBJECT_ALT_NAME: [u8; 3] = [0x55, 0x1d, 0x11];
    pub const BASIC_CONSTRAINTS: [u8; 3] = [0x55, 0x1d, 0x13];
    pub const AUTHORITY_KEY_ID: [u8; 3] = [0x55, 0x1d, 0x23];
    pub const EXT_KEY_USAGE: [u8; 3] = [0x55, 0x1d, 0x25];
    pub const SERVER_AUTH: [u8; 8] = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
    pub const CLIENT_AUTH: [u8; 8] = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];
    pub const CODE_SIGNING: [u8; 8] = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03];
}

/// Extended key usage of an end-entity certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Purpose {
    /// TLS server (`id-kp-serverAuth`).
    ServerAuth,
    /// TLS client (`id-kp-clientAuth`).
    ClientAuth,
    /// Code signing (`id-kp-codeSigning`).
    CodeSigning,
}

impl Purpose {
    pub(crate) fn oid(self) -> &'static [u8] {
        match self {
            Purpose::ServerAuth => &oid::SERVER_AUTH,
            Purpose::ClientAuth => &oid::CLIENT_AUTH,
            Purpose::CodeSigning => &oid::CODE_SIGNING,
        }
    }
}

/// A DER certificate signed with ML-DSA.
#[derive(Clone, PartialEq, Eq)]
pub struct Certificate {
    der: Vec<u8>,
}

impl std::fmt::Debug for Certificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let subject = self
            .parsed()
            .map(|c| c.subject().to_string())
            .unwrap_or_default();
        f.debug_struct("Certificate")
            .field("subject", &subject)
            .finish()
    }
}

impl Certificate {
    /// Wrap DER bytes. The certificate must parse and use ML-DSA; validity is checked by
    /// [`crate::verify_chain`].
    pub fn from_der(der: &[u8]) -> Result<Self> {
        let cert = Certificate { der: der.to_vec() };
        let parsed = cert.parsed()?;
        crate::Algorithm::from_identifier(&parsed.signature_algorithm)?;
        Ok(cert)
    }

    /// Parse one PEM `CERTIFICATE`.
    pub fn from_pem(text: &str) -> Result<Self> {
        Self::from_der(&pem::decode("CERTIFICATE", text)?)
    }

    /// Parse every PEM `CERTIFICATE` in `text` (a bundle or chain file).
    pub fn all_from_pem(text: &str) -> Result<Vec<Self>> {
        pem::decode_all("CERTIFICATE", text)?
            .iter()
            .map(|d| Self::from_der(d))
            .collect()
    }

    /// DER encoding.
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// PEM encoding.
    pub fn to_pem(&self) -> String {
        pem::encode("CERTIFICATE", &self.der)
    }

    /// The subject's public key (ML-DSA only).
    pub fn public_key(&self) -> Result<PublicKey> {
        PublicKey::from_parsed(self.parsed()?.public_key())
    }

    /// The subject distinguished name, e.g. `CN=api.example.com`.
    pub fn subject(&self) -> Result<String> {
        Ok(self.parsed()?.subject().to_string())
    }

    pub(crate) fn parsed(&self) -> Result<X509Certificate<'_>> {
        let (rest, cert) = X509Certificate::from_der(&self.der)?;
        if !rest.is_empty() {
            return Err(Error::Malformed("trailing data after certificate"));
        }
        Ok(cert)
    }
}

/// What to put in a new certificate.
#[derive(Clone, Debug)]
pub struct CertificateParams {
    common_name: String,
    organization: Option<String>,
    days: u32,
    is_ca: bool,
    path_len: Option<u8>,
    dns_names: Vec<String>,
    purposes: Vec<Purpose>,
    not_before: Option<i64>,
}

impl CertificateParams {
    /// A certification authority valid for `days` days.
    pub fn ca(common_name: &str, days: u32) -> Self {
        Self::new(common_name, days, true)
    }

    /// An end-entity certificate valid for `days` days.
    pub fn end_entity(common_name: &str, days: u32) -> Self {
        Self::new(common_name, days, false)
    }

    fn new(common_name: &str, days: u32, is_ca: bool) -> Self {
        CertificateParams {
            common_name: common_name.to_owned(),
            organization: None,
            days,
            is_ca,
            path_len: None,
            dns_names: Vec::new(),
            purposes: Vec::new(),
            not_before: None,
        }
    }

    /// Organization (`O=`).
    pub fn organization(mut self, o: &str) -> Self {
        self.organization = Some(o.to_owned());
        self
    }

    /// For a CA: the maximum number of intermediate CAs below it.
    pub fn path_len(mut self, n: u8) -> Self {
        self.path_len = Some(n);
        self
    }

    /// DNS names for the subject alternative name extension.
    pub fn dns_names(mut self, names: &[&str]) -> Self {
        self.dns_names
            .extend(names.iter().map(|n| n.to_ascii_lowercase()));
        self
    }

    /// Add an extended key usage (end entities).
    pub fn purpose(mut self, p: Purpose) -> Self {
        if !self.purposes.contains(&p) {
            self.purposes.push(p);
        }
        self
    }

    /// Start of validity (Unix seconds). Default: now minus one minute.
    pub fn not_before(mut self, unix: i64) -> Self {
        self.not_before = Some(unix);
        self
    }

    fn check(&self) -> Result<()> {
        let cn = self.common_name.chars().count();
        if cn == 0 || cn > 64 {
            return Err(Error::InvalidParams(
                "common name must be 1 to 64 characters",
            ));
        }
        if self.days == 0 {
            return Err(Error::InvalidParams("validity must be at least one day"));
        }
        if self.is_ca && (!self.dns_names.is_empty() || !self.purposes.is_empty()) {
            return Err(Error::InvalidParams(
                "CA certificates carry no DNS names or purposes here",
            ));
        }
        if !self.is_ca && self.path_len.is_some() {
            return Err(Error::InvalidParams(
                "path length applies to CA certificates only",
            ));
        }
        for name in &self.dns_names {
            if !valid_dns_name(name) {
                return Err(Error::InvalidParams("invalid DNS name"));
            }
        }
        Ok(())
    }

    fn name(&self) -> Vec<u8> {
        let rdn = |oid: &[u8], value: &str| der::set(&[&seq(&[&der::oid(oid), &der::utf8(value)])]);
        let mut rdns = Vec::new();
        if let Some(o) = &self.organization {
            rdns.extend(rdn(&oid::ORGANIZATION, o));
        }
        rdns.extend(rdn(&oid::COMMON_NAME, &self.common_name));
        der::tlv(der::SEQUENCE, &rdns)
    }

    /// A self-signed certificate for `key` (normally a root CA).
    pub fn self_signed(&self, key: &PrivateKey) -> Result<Certificate> {
        self.check()?;
        let name = self.name();
        let ski = key.public_key().key_identifier();
        self.build(key.public_key(), &name, &name, &ski, key)
    }

    /// A certificate for `subject` signed by the CA `issuer` / `issuer_key`.
    pub fn issue(
        &self,
        subject: &PublicKey,
        issuer: &Certificate,
        issuer_key: &PrivateKey,
    ) -> Result<Certificate> {
        self.check()?;
        let parsed = issuer.parsed()?;
        if issuer.public_key()? != *issuer_key.public_key() {
            return Err(Error::InvalidParams(
                "issuer key does not match the issuer certificate",
            ));
        }
        let is_ca = parsed.extensions().iter().any(
            |e| matches!(e.parsed_extension(), ParsedExtension::BasicConstraints(bc) if bc.ca),
        );
        if !is_ca {
            return Err(Error::InvalidParams("issuer certificate is not a CA"));
        }
        let aki = parsed
            .extensions()
            .iter()
            .find_map(|e| match e.parsed_extension() {
                ParsedExtension::SubjectKeyIdentifier(id) => Some(id.0.to_vec()),
                _ => None,
            })
            .unwrap_or_else(|| issuer_key.public_key().key_identifier().to_vec());
        self.build(
            subject,
            &self.name(),
            parsed.subject().as_raw(),
            &aki,
            issuer_key,
        )
    }

    fn build(
        &self,
        subject_key: &PublicKey,
        subject: &[u8],
        issuer: &[u8],
        authority_key_id: &[u8],
        signer: &PrivateKey,
    ) -> Result<Certificate> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let not_before = self.not_before.unwrap_or(now - 60);
        let not_after = not_before + i64::from(self.days) * 86_400 - 1;

        let mut serial = [0u8; 16];
        getrandom::fill(&mut serial).map_err(|_| Error::Rng)?;
        serial[0] = (serial[0] & 0x7f) | 0x01; // positive, full 16 bytes

        let alg_id = signer.algorithm().algorithm_identifier();
        let ext = |oid: &[u8], critical: bool, value: &[u8]| -> Vec<u8> {
            if critical {
                seq(&[&der::oid(oid), &der::boolean(true), &der::octets(value)])
            } else {
                seq(&[&der::oid(oid), &der::octets(value)])
            }
        };
        let mut extensions = Vec::new();
        if self.is_ca {
            let path_len = self.path_len.map(|n| der::uint(&[n])).unwrap_or_default();
            extensions.push(ext(
                &oid::BASIC_CONSTRAINTS,
                true,
                &seq(&[&der::boolean(true), &path_len]),
            ));
            // keyCertSign (bit 5) and cRLSign (bit 6).
            extensions.push(ext(&oid::KEY_USAGE, true, &der::bits(1, &[0x06])));
        } else {
            extensions.push(ext(&oid::BASIC_CONSTRAINTS, true, &seq(&[])));
            // digitalSignature (bit 0).
            extensions.push(ext(&oid::KEY_USAGE, true, &der::bits(7, &[0x80])));
            if !self.purposes.is_empty() {
                let oids: Vec<Vec<u8>> = self.purposes.iter().map(|p| der::oid(p.oid())).collect();
                extensions.push(ext(
                    &oid::EXT_KEY_USAGE,
                    false,
                    &der::tlv(der::SEQUENCE, &oids.concat()),
                ));
            }
            if !self.dns_names.is_empty() {
                let names: Vec<Vec<u8>> = self
                    .dns_names
                    .iter()
                    .map(|n| der::implicit(2, n.as_bytes()))
                    .collect();
                // Critical when the subject name is empty; here CN is always present.
                extensions.push(ext(
                    &oid::SUBJECT_ALT_NAME,
                    false,
                    &der::tlv(der::SEQUENCE, &names.concat()),
                ));
            }
        }
        extensions.push(ext(
            &oid::SUBJECT_KEY_ID,
            false,
            &der::octets(&subject_key.key_identifier()),
        ));
        extensions.push(ext(
            &oid::AUTHORITY_KEY_ID,
            false,
            &seq(&[&der::implicit(0, authority_key_id)]),
        ));

        let tbs = seq(&[
            &der::explicit(0, &der::uint(&[2])),
            &der::uint(&serial),
            &alg_id,
            issuer,
            &seq(&[&der::time(not_before), &der::time(not_after)]),
            subject,
            &subject_key.to_spki_der(),
            &der::explicit(3, &der::tlv(der::SEQUENCE, &extensions.concat())),
        ]);
        let signature = signer.sign(&tbs)?;
        let cert = Certificate {
            der: seq(&[&tbs, &alg_id, &der::bits(0, &signature)]),
        };
        // Parse back and verify our own signature before handing it out.
        let parsed = cert.parsed()?;
        signer.public_key().verify(
            parsed.tbs_certificate.as_ref(),
            &parsed.signature_value.data,
        )?;
        Ok(cert)
    }
}

/// Lower-case LDH labels, optionally with a leading `*.` wildcard; at least two labels.
pub(crate) fn valid_dns_name(name: &str) -> bool {
    let name = name.strip_prefix("*.").unwrap_or(name);
    let labels: Vec<&str> = name.split('.').collect();
    name.len() <= 253
        && labels.len() >= 2
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}
