//! Classification of SSH key exchange algorithm names.

/// What a key exchange algorithm offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KexClass {
    /// Hybrid classical + ML-KEM (NIST FIPS 203), e.g. `mlkem768x25519-sha256`.
    HybridMlKem,
    /// Hybrid classical + Streamlined NTRU Prime (post-quantum, not a NIST standard), e.g.
    /// `sntrup761x25519-sha512`.
    HybridSntrup,
    /// Classical (EC)DH only: breakable by a large quantum computer.
    Classical,
    /// Classical and weak today (SHA-1 or a 1024-bit group).
    Weak,
    /// Not a key exchange: an extension marker such as `ext-info-s` or strict KEX.
    Marker,
    /// Unknown name.
    Unknown,
}

impl KexClass {
    /// Does this algorithm resist a quantum attacker (as a hybrid)?
    pub fn is_post_quantum(self) -> bool {
        matches!(self, KexClass::HybridMlKem | KexClass::HybridSntrup)
    }
}

/// Classify a key exchange name as it appears in `KEXINIT` or `KexAlgorithms`.
pub fn classify_kex(name: &str) -> KexClass {
    match name {
        "mlkem768x25519-sha256" | "mlkem768nistp256-sha256" | "mlkem1024nistp384-sha384" => {
            KexClass::HybridMlKem
        }
        "sntrup761x25519-sha512" | "sntrup761x25519-sha512@openssh.com" => KexClass::HybridSntrup,
        "diffie-hellman-group1-sha1"
        | "diffie-hellman-group14-sha1"
        | "diffie-hellman-group-exchange-sha1"
        | "gss-group1-sha1-toWM5Slw5Ew8Mqkay+al2g==" => KexClass::Weak,
        "curve25519-sha256"
        | "curve25519-sha256@libssh.org"
        | "curve448-sha512"
        | "ecdh-sha2-nistp256"
        | "ecdh-sha2-nistp384"
        | "ecdh-sha2-nistp521"
        | "diffie-hellman-group14-sha256"
        | "diffie-hellman-group15-sha512"
        | "diffie-hellman-group16-sha512"
        | "diffie-hellman-group17-sha512"
        | "diffie-hellman-group18-sha512"
        | "diffie-hellman-group-exchange-sha256" => KexClass::Classical,
        n if n.starts_with("ext-info-") || n.starts_with("kex-strict-") => KexClass::Marker,
        _ => KexClass::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classes() {
        assert!(classify_kex("mlkem768x25519-sha256").is_post_quantum());
        assert!(classify_kex("sntrup761x25519-sha512@openssh.com").is_post_quantum());
        assert_eq!(classify_kex("curve25519-sha256"), KexClass::Classical);
        assert_eq!(classify_kex("diffie-hellman-group1-sha1"), KexClass::Weak);
        assert_eq!(
            classify_kex("kex-strict-s-v00@openssh.com"),
            KexClass::Marker
        );
        assert_eq!(classify_kex("made-up"), KexClass::Unknown);
    }
}
