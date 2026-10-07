//! Audit of the OpenSSH `KexAlgorithms` directive (sshd_config(5), ssh_config(5)).

use crate::kex::classify_kex;

/// Hybrid post-quantum key exchanges in OpenSSH's default list (9.0 and later).
const DEFAULT_PQ: [&str; 3] = [
    "mlkem768x25519-sha256",
    "sntrup761x25519-sha512",
    "sntrup761x25519-sha512@openssh.com",
];

/// Result of evaluating a `KexAlgorithms` value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KexAudit {
    /// An explicit list that includes a hybrid post-quantum key exchange. `pq_first` tells
    /// whether one comes first, which matters on the client side (`ssh_config`), where the
    /// client's order decides the negotiated algorithm.
    PostQuantum {
        /// The post-quantum entries of the list.
        pq: Vec<String>,
        /// A post-quantum entry is first in the list.
        pq_first: bool,
    },
    /// An explicit list without any hybrid post-quantum key exchange.
    ClassicalOnly {
        /// The list.
        list: Vec<String>,
    },
    /// `-list` removes every post-quantum hybrid from the built-in default.
    RemovesPostQuantum {
        /// The removal patterns.
        removed: Vec<String>,
    },
    /// `+list` / `^list`, or a `-list` that leaves a hybrid in place: the defaults (which
    /// include post-quantum hybrids since OpenSSH 9.0) stay available.
    KeepsDefault,
}

/// OpenSSH wildcard match: `*` (any sequence) and `?` (one character).
///
/// Iterative, remembering only the last `*`: O(pattern x name) even for inputs such as
/// `*****...*x` that make the naive recursion exponential (configuration files are untrusted
/// input for the scanner).
fn wildcard(pattern: &[u8], name: &[u8]) -> bool {
    let (mut p, mut n) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while n < name.len() {
        match pattern.get(p) {
            Some(b'*') => {
                star = Some((p, n));
                p += 1;
            }
            Some(&c) if c == b'?' || c == name[n] => {
                p += 1;
                n += 1;
            }
            _ => match star {
                // Let the last `*` absorb one more character and retry.
                Some((sp, sn)) => {
                    star = Some((sp, sn + 1));
                    p = sp + 1;
                    n = sn + 1;
                }
                None => return false,
            },
        }
    }
    pattern[p..].iter().all(|&c| c == b'*')
}

/// Evaluate the value of a `KexAlgorithms` directive (everything after the keyword).
pub fn audit_kex_directive(value: &str) -> KexAudit {
    let value = value.trim().trim_matches('"');
    let list = |s: &str| -> Vec<String> {
        s.split(',')
            .map(str::trim)
            .filter(|x| !x.is_empty())
            .map(str::to_owned)
            .collect()
    };
    match value.as_bytes().first() {
        Some(b'+') | Some(b'^') => KexAudit::KeepsDefault,
        Some(b'-') => {
            let removed = list(&value[1..]);
            let survivors = DEFAULT_PQ
                .iter()
                .filter(|pq| {
                    !removed
                        .iter()
                        .any(|r| wildcard(r.as_bytes(), pq.as_bytes()))
                })
                .count();
            if survivors == 0 {
                KexAudit::RemovesPostQuantum { removed }
            } else {
                KexAudit::KeepsDefault
            }
        }
        _ => {
            let list = list(value);
            let pq: Vec<String> = list
                .iter()
                .filter(|k| classify_kex(k).is_post_quantum())
                .cloned()
                .collect();
            if pq.is_empty() {
                KexAudit::ClassicalOnly { list }
            } else {
                let pq_first = list
                    .first()
                    .is_some_and(|k| classify_kex(k).is_post_quantum());
                KexAudit::PostQuantum { pq, pq_first }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directive_semantics() {
        assert_eq!(
            audit_kex_directive("curve25519-sha256,ecdh-sha2-nistp256"),
            KexAudit::ClassicalOnly {
                list: vec!["curve25519-sha256".into(), "ecdh-sha2-nistp256".into()]
            }
        );
        assert_eq!(
            audit_kex_directive("mlkem768x25519-sha256,curve25519-sha256"),
            KexAudit::PostQuantum {
                pq: vec!["mlkem768x25519-sha256".into()],
                pq_first: true
            }
        );
        assert!(matches!(
            audit_kex_directive("curve25519-sha256,sntrup761x25519-sha512@openssh.com"),
            KexAudit::PostQuantum {
                pq_first: false,
                ..
            }
        ));
        assert_eq!(
            audit_kex_directive("+diffie-hellman-group14-sha256"),
            KexAudit::KeepsDefault
        );
        assert_eq!(
            audit_kex_directive("^curve25519-sha256"),
            KexAudit::KeepsDefault
        );
        assert_eq!(audit_kex_directive("-sntrup*"), KexAudit::KeepsDefault); // mlkem remains
        assert!(matches!(
            audit_kex_directive("-sntrup*,mlkem*"),
            KexAudit::RemovesPostQuantum { .. }
        ));
        assert!(matches!(
            audit_kex_directive("-*"),
            KexAudit::RemovesPostQuantum { .. }
        ));
        assert_eq!(
            audit_kex_directive("-diffie-hellman-group14-sha1"),
            KexAudit::KeepsDefault
        );
    }

    #[test]
    fn wildcards() {
        assert!(wildcard(b"sntrup*", b"sntrup761x25519-sha512@openssh.com"));
        assert!(wildcard(b"*x25519*", b"mlkem768x25519-sha256"));
        assert!(wildcard(b"mlkem768x25519-sha25?", b"mlkem768x25519-sha256"));
        assert!(!wildcard(b"mlkem1024*", b"mlkem768x25519-sha256"));
        assert!(wildcard(b"*", b""));
        assert!(wildcard(b"", b""));
        assert!(!wildcard(b"", b"a"));
        assert!(!wildcard(b"?", b""));
        assert!(wildcard(b"a*b*c", b"aXbYbZc"));
        assert!(!wildcard(b"a*b*c", b"aXbYbZ"));
        assert!(wildcard(b"*sha256", b"mlkem768x25519-sha256"));
        assert!(!wildcard(b"*sha512", b"mlkem768x25519-sha256"));
        assert!(wildcard(b"s*1*@*", b"sntrup761x25519-sha512@openssh.com"));
    }

    #[test]
    fn wildcard_agrees_with_the_textbook_recursion_on_every_short_input() {
        fn reference(pattern: &[u8], name: &[u8]) -> bool {
            match (pattern.split_first(), name.split_first()) {
                (None, None) => true,
                (Some((b'*', p)), _) => {
                    reference(p, name) || (!name.is_empty() && reference(pattern, &name[1..]))
                }
                (Some((b'?', p)), Some((_, n))) => reference(p, n),
                (Some((a, p)), Some((b, n))) if a == b => reference(p, n),
                _ => false,
            }
        }
        // All patterns over {a, b, *, ?} up to length 5 against all names over {a, b} up to 5.
        fn all(alphabet: &[u8], max: usize) -> Vec<Vec<u8>> {
            let mut out = vec![vec![]];
            let mut layer = vec![vec![]];
            for _ in 0..max {
                layer = layer
                    .iter()
                    .flat_map(|w: &Vec<u8>| {
                        alphabet.iter().map(move |&c| [w.as_slice(), &[c]].concat())
                    })
                    .collect();
                out.extend(layer.iter().cloned());
            }
            out
        }
        let names = all(b"ab", 5);
        for pattern in all(b"ab*?", 5) {
            for name in &names {
                assert_eq!(wildcard(&pattern, name), reference(&pattern, name));
            }
        }
    }

    #[test]
    fn wildcards_are_not_exponential() {
        // Took minutes with the recursive matcher (found by the fuzzer).
        let evil = format!("-{}x", "*".repeat(4000));
        let start = std::time::Instant::now();
        assert_eq!(audit_kex_directive(&evil), KexAudit::KeepsDefault);
        let many = format!(
            "-{}",
            vec!["*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*b"; 200].join(",")
        );
        assert_eq!(audit_kex_directive(&many), KexAudit::KeepsDefault);
        // Wall-clock bound: meaningless under the Miri interpreter.
        if !cfg!(miri) {
            assert!(start.elapsed() < std::time::Duration::from_secs(2));
        }
    }
}
