/// Where a finding came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// A mention in source code or a configuration file.
    Code,
    /// A parsed X.509 certificate.
    Certificate,
    /// A private key file (only its algorithm is recorded, never the key).
    PrivateKey,
    /// A public key file.
    PublicKey,
}

impl Source {
    /// Stable identifier used in machine-readable output.
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Code => "code",
            Source::Certificate => "certificate",
            Source::PrivateKey => "private-key",
            Source::PublicKey => "public-key",
        }
    }
}

/// Algorithm family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Family {
    /// RSA (encryption or signatures).
    Rsa,
    /// DSA.
    Dsa,
    /// Elliptic-curve algorithms without a clearer purpose (NIST curves, secp256k1).
    Ecc,
    /// ECDSA.
    Ecdsa,
    /// ECDH.
    Ecdh,
    /// EdDSA (Ed25519, Ed448).
    EdDsa,
    /// X25519 / X448 key agreement.
    X25519,
    /// Finite-field Diffie-Hellman.
    Dh,
    /// AES with a 128-bit key.
    Aes128,
    /// AES with a 256-bit key.
    Aes256,
    /// ChaCha20 family.
    ChaCha20,
    /// Broken hash: MD5 / SHA-1.
    BrokenHash,
    /// Broken or obsolete cipher: DES, 3DES, RC4, RC2, Blowfish, ECB mode.
    BrokenCipher,
    /// Obsolete TLS / SSL versions.
    LegacyProtocol,
    /// Post-quantum KEM (ML-KEM / Kyber / sntrup / HQC).
    PqKem,
    /// Post-quantum signature (ML-DSA / SLH-DSA / FN-DSA and their earlier names).
    PqSignature,
    /// Hybrid classical + post-quantum key exchange.
    HybridKem,
}

/// What the algorithm is used for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Purpose {
    /// Key exchange / key agreement / key transport.
    KeyExchange,
    /// Digital signatures.
    Signature,
    /// Could be either (for example a bare "RSA" or "P-256").
    KeyExchangeOrSignature,
    /// Symmetric encryption, hashing or protocol configuration.
    Other,
}

/// How a finding is classified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Risk {
    /// Fine as is.
    Info,
    /// Post-quantum algorithm in use.
    PostQuantum,
    /// Broken or obsolete regardless of quantum computers.
    Weak,
    /// Breakable by a large quantum computer (Shor).
    QuantumVulnerable,
}

impl Risk {
    /// Stable identifier used in machine-readable output.
    pub fn as_str(self) -> &'static str {
        match self {
            Risk::Info => "info",
            Risk::PostQuantum => "post-quantum",
            Risk::Weak => "weak",
            Risk::QuantumVulnerable => "quantum-vulnerable",
        }
    }
}

/// One finding.
#[derive(Debug, Clone)]
pub struct Finding {
    /// File path as scanned.
    pub path: String,
    /// 1-based line number for code findings.
    pub line: Option<usize>,
    /// Origin of the finding.
    pub source: Source,
    /// Human-readable algorithm, for example `RSA-2048` or `ECDSA P-256`.
    pub algorithm: String,
    /// Family.
    pub family: Family,
    /// Purpose.
    pub purpose: Purpose,
    /// Classification.
    pub risk: Risk,
    /// Migration priority tier (`T0`..`T4`, `PQ`), see ADR-0003.
    pub tier: &'static str,
    /// Extra context (certificate subject and expiry, matched text, ...).
    pub detail: String,
    /// What to do about it.
    pub advice: &'static str,
    /// True for certificates that stay valid past 2030 (long-lived trust).
    pub long_lived: bool,
}

/// Scan result.
#[derive(Debug, Default)]
pub struct Report {
    /// Findings in discovery order.
    pub findings: Vec<Finding>,
    /// Files that were read and analysed.
    pub files_scanned: usize,
    /// Files skipped (binary, too large, unreadable).
    pub files_skipped: usize,
}

impl Report {
    /// Number of findings with the given risk.
    pub fn count(&self, risk: Risk) -> usize {
        self.findings.iter().filter(|f| f.risk == risk).count()
    }

    /// The most severe risk present, if any.
    pub fn worst(&self) -> Option<Risk> {
        self.findings.iter().map(|f| f.risk).max()
    }
}

/// Migration tier and advice for a family and purpose (ADR-0003).
pub(crate) fn classify(
    family: Family,
    purpose: Purpose,
    long_lived: bool,
) -> (Risk, &'static str, &'static str) {
    use Family::*;
    match family {
        Rsa | Ecc | Ecdh | Dh | X25519 | Dsa | Ecdsa | EdDsa => {
            let key_exchange =
                matches!(purpose, Purpose::KeyExchange) || matches!(family, Ecdh | Dh | X25519);
            if key_exchange {
                (
                    Risk::QuantumVulnerable,
                    "T0",
                    "Key exchange is exposed to harvest-now-decrypt-later. Move to a hybrid KEM \
                     (vpqc profile `standard`: X25519 + ML-KEM-768).",
                )
            } else if matches!(purpose, Purpose::Signature) && long_lived {
                (
                    Risk::QuantumVulnerable,
                    "T1",
                    "Long-lived signature. Use a composite signature (vpqc profile `standard`, or \
                     `high` for the longest lifetimes).",
                )
            } else if matches!(purpose, Purpose::Signature) {
                (
                    Risk::QuantumVulnerable,
                    "T1/T2",
                    "Signature. Acceptable for short-lived authentication (vpqc `fast-auth`); use a \
                     composite signature for anything long-lived (certificates, firmware, archives).",
                )
            } else {
                (
                    Risk::QuantumVulnerable,
                    "T0/T1",
                    "Quantum-vulnerable public-key algorithm; check whether it is used for key \
                     exchange (T0, migrate first) or signatures (T1/T2).",
                )
            }
        }
        Aes128 => (
            Risk::Info,
            "T3",
            "AES-128 remains acceptable; consider AES-256 for data that must stay secret for decades.",
        ),
        Aes256 | ChaCha20 => (
            Risk::Info,
            "T3",
            "Symmetric cipher with a 256-bit key: unaffected in practice.",
        ),
        BrokenHash => (
            Risk::Weak,
            "T4",
            "Broken for collision resistance regardless of quantum computers; use SHA-256/384 or SHA-3.",
        ),
        BrokenCipher => (
            Risk::Weak,
            "T4",
            "Obsolete or weak cipher/mode regardless of quantum computers; use AES-256-GCM or ChaCha20-Poly1305.",
        ),
        LegacyProtocol => (
            Risk::Weak,
            "T4",
            "Obsolete protocol version; require TLS 1.3 and a hybrid group such as X25519MLKEM768.",
        ),
        PqKem | PqSignature => (
            Risk::PostQuantum,
            "PQ",
            "Post-quantum algorithm. Prefer standardized names (ML-KEM/ML-DSA) and keep a classical \
             component (hybrid) until the ecosystem matures.",
        ),
        HybridKem => (
            Risk::PostQuantum,
            "PQ",
            "Hybrid classical + post-quantum key exchange: the recommended posture.",
        ),
    }
}
