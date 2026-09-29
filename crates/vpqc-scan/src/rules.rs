//! Line-based pattern rules for source and configuration files.

use std::sync::OnceLock;

use regex::Regex;

use crate::model::{Family, Purpose};

pub(crate) struct Rule {
    pub(crate) regex: Regex,
    pub(crate) family: Family,
    pub(crate) purpose: Purpose,
    pub(crate) label: &'static str,
}

fn rule(pattern: &str, family: Family, purpose: Purpose, label: &'static str) -> Rule {
    Rule {
        regex: Regex::new(pattern).expect("valid built-in pattern"),
        family,
        purpose,
        label,
    }
}

/// Matches that mean a line already uses a hybrid or post-quantum construction; plain X25519 /
/// ECDH mentions on the same line are then not reported as classical-only.
pub(crate) fn hybrid_marker() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)X25519[-_ ]?(ML-?KEM|Kyber)|SecP\d+r1[-_ ]?ML-?KEM|mlkem\d*x25519|sntrup761x25519|x25519-?mlkem|X-?Wing|MLKEM\d+-(P\d+|X25519)")
            .expect("valid built-in pattern")
    })
}

pub(crate) fn rules() -> &'static [Rule] {
    static RULES: OnceLock<Vec<Rule>> = OnceLock::new();
    RULES.get_or_init(|| {
        use Family::*;
        use Purpose::*;
        vec![
            // Post-quantum and hybrid (checked first).
            rule(r"(?i)X25519[-_ ]?(ML-?KEM|Kyber)\d*|SecP\d+r1[-_ ]?ML-?KEM\d*|mlkem\d*x25519|sntrup761x25519|X-?Wing|MLKEM\d+-(P\d+|X25519)", HybridKem, KeyExchange, "hybrid key exchange"),
            rule(r"(?i)\bML-?KEM(-?(512|768|1024))?\b|\bKyber(512|768|1024)?\b|\bsntrup761\b|\bHQC(-?(128|192|256))?\b|\bmlkem\w*", PqKem, KeyExchange, "post-quantum KEM"),
            rule(r"(?i)\bML-?DSA(-?(44|65|87))?\b|\bDilithium[2-5]?\b|\bSLH-?DSA\b|\bSPHINCS\+?|\bFN-?DSA\b|\bFalcon(-?(512|1024))?\b|\bXMSS\b|\bmldsa\w*", PqSignature, Signature, "post-quantum signature"),
            // Key exchange.
            rule(r"ECDH|createECDH", Ecdh, KeyExchange, "ECDH"),
            rule(r"\bDiffie[- ]?Hellman\b|\bDHE-|\bdhparam\b|\bffdhe\d+|\bmodp_?\d{4}\b|createDiffieHellman|\bDH_generate", Dh, KeyExchange, "finite-field Diffie-Hellman"),
            rule(r"\b[Xx]25519\b|\b[Xx]448\b|\bcurve25519\b", X25519, KeyExchange, "X25519 / X448"),
            // RSA (purpose depends on the mention).
            rule(r"RSAES|RSA/ECB|RSA_PKCS1|rsa[-_]?oaep|RSA-OAEP|RSA_public_encrypt|RSA_private_decrypt", Rsa, KeyExchange, "RSA encryption / key transport"),
            rule(r"\bRS(256|384|512)\b|\bPS(256|384|512)\b|RSASSA|rsa-sha\d+|sha\d+WithRSA|\bssh-rsa\b|rsa_sign|RSA_sign", Rsa, Signature, "RSA signature"),
            rule(r"(?:^|[^A-Za-z])RSA|[a-z]RSA(?:[^a-z]|$)|\brsa[._/-]|[\x22'`]rsa[\x22'`]|\bgenrsa\b|\brsa\b", Rsa, KeyExchangeOrSignature, "RSA"),
            // Signatures.
            rule(r"ECDSA|\bES(256|384|512)\b|ecdsa-sha2|\becdsa\b", Ecdsa, Signature, "ECDSA"),
            rule(r"\bEd25519\b|\bEd448\b|EdDSA|\bssh-ed25519\b", EdDsa, Signature, "EdDSA"),
            rule(r"(?:^|[^A-Za-z-])DSA\b|\bssh-dss\b|\bDSA_", Dsa, Signature, "DSA"),
            // Curves without a clear purpose.
            rule(r"\b(secp256r1|prime256v1|secp384r1|secp521r1|secp256k1|P-256|P-384|P-521|NIST P-?(256|384|521))\b", Ecc, KeyExchangeOrSignature, "NIST/SECG curve"),
            // Symmetric and hashes.
            rule(r"(?i)\bAES[-_ /]?128\b|\baes128\b", Aes128, Other, "AES-128"),
            rule(r"(?i)\bAES[-_ /]?256\b|\baes256\b|\bchacha20", Aes256, Other, "256-bit symmetric cipher"),
            rule(r"\bMD5\b|\bmd5\b|\bSHA-?1\b|\bsha1\b", BrokenHash, Other, "MD5 / SHA-1"),
            rule(r"\b3DES\b|\bDESede\b|\bTripleDES\b|\bDES\b|\bRC4\b|\bRC2\b|\bARCFOUR\b|\bBlowfish\b|\bAES[-_/]?ECB\b|/ECB/", BrokenCipher, Other, "obsolete cipher or mode"),
            rule(r"\bSSLv2\b|\bSSLv3\b|\bTLSv1\b|\bTLSv1\.0\b|\bTLSv1\.1\b|\bTLS 1\.0\b|\bTLS 1\.1\b", LegacyProtocol, Other, "obsolete TLS/SSL version"),
        ]
    })
}
