//! `vpqc lint`: concrete migration suggestions for the scan findings that are code.
//!
//! The scanner finds *mentions* of vulnerable algorithms. This module maps each such finding in a
//! source file to the vpqc API call that replaces the usual use, in the language of the file.
//! The suggestions are starting points, not drop-in replacements: vpqc's sealed boxes and
//! signatures use their own formats (they do not read RSA-OAEP, ECIES or PKCS#1 data), and
//! `sign` needs a domain-separation context.

use std::fmt::Write;
use std::path::Path;

use serde_json::{Value, json};

use crate::model::{Family, Finding, Purpose, Report, Risk, Source};

/// What the finding is used for, as far as it can be told.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Use {
    /// Key exchange, key agreement or public-key encryption: migrate first (tier T0).
    Encrypt,
    /// Signatures (tier T1 or T2).
    Sign,
    /// A public-key algorithm of unknown purpose (tier T0/T1).
    Either,
    /// A weak algorithm that quantum computers do not matter for (tier T4).
    Weak,
}

/// A suggestion for one finding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Suggestion {
    /// Language of the source file, as named in the output.
    pub language: &'static str,
    /// Replacement snippets, one per use (`Either` gives both).
    pub snippets: Vec<(&'static str, &'static str)>,
    /// What to watch out for.
    pub caveat: &'static str,
}

fn language(path: &str) -> Option<&'static str> {
    let ext = Path::new(path).extension()?.to_str()?.to_ascii_lowercase();
    Some(match ext.as_str() {
        "py" => "Python",
        "js" | "mjs" | "cjs" | "jsx" | "ts" | "tsx" => "JavaScript/TypeScript",
        "go" => "Go",
        "java" | "kt" | "kts" => "Java/Kotlin",
        "php" => "PHP",
        "rb" => "Ruby",
        "cs" => "C#",
        "dart" => "Dart",
        "rs" => "Rust",
        "c" | "h" | "cc" | "cpp" | "hpp" => "C/C++",
        _ => return None,
    })
}

fn usage(f: &Finding) -> Option<Use> {
    match f.risk {
        Risk::Weak => Some(Use::Weak),
        Risk::QuantumVulnerable => Some(
            if matches!(f.purpose, Purpose::KeyExchange)
                || matches!(f.family, Family::Ecdh | Family::Dh | Family::X25519)
            {
                Use::Encrypt
            } else if matches!(f.purpose, Purpose::Signature) {
                Use::Sign
            } else {
                Use::Either
            },
        ),
        _ => None,
    }
}

fn encrypt(lang: &str) -> &'static str {
    match lang {
        "Python" => {
            "keys = vpqc.generate_encryption_keypair()\nsealed = vpqc.seal(keys.public, data, aad=b\"app/v1\")\ndata = vpqc.unseal(keys.secret, sealed, aad=b\"app/v1\")"
        }
        "JavaScript/TypeScript" => {
            "const keys = vpqc.generateEncryptionKeypair();\nconst sealed = vpqc.seal(keys.publicKey, data, aad);\nconst plain = vpqc.unseal(keys.secretKey, sealed, aad);"
        }
        "Go" => {
            "pk, sk, _ := vpqc.GenerateEncryptionKeypair(vpqc.ProfileStandard)\nsealed, _ := vpqc.Seal(pk, data, aad)\nplain, _ := vpqc.Open(sk, sealed, aad)"
        }
        "Java/Kotlin" => {
            "KeyPair keys = Vpqc.generateEncryptionKeypair(Profile.STANDARD);\nbyte[] sealed = Vpqc.seal(keys.publicKey(), data, aad);\nbyte[] plain = Vpqc.open(keys.secretKey(), sealed, aad);"
        }
        "PHP" => {
            "$keys = Vpqc::generateEncryptionKeypair();\n$sealed = Vpqc::seal($keys->public, $data, 'app/v1');\n$plain = Vpqc::open($keys->secret, $sealed, 'app/v1');"
        }
        "Ruby" => {
            "keys = Vpqc.generate_encryption_keypair\nsealed = Vpqc.seal(keys.public, data, aad: \"app/v1\")\nplain = Vpqc.unseal(keys.secret, sealed, aad: \"app/v1\")"
        }
        "C#" => {
            "var keys = Vpqc.GenerateEncryptionKeypair();\nvar sealedMsg = Vpqc.Seal(keys.Public, data, aad);\nvar plain = Vpqc.Open(keys.Secret, sealedMsg, aad);"
        }
        "Dart" => {
            "final keys = Vpqc.generateEncryptionKeypair();\nfinal sealed = Vpqc.seal(keys.public, data, aad: aad);\nfinal plain = Vpqc.open(keys.secret, sealed, aad: aad);"
        }
        "Rust" => {
            "let keys = vpqc::encryption::generate(Profile::Standard)?;\nlet sealed = vpqc::encryption::seal(&keys.public, data, b\"app/v1\")?;\nlet plain = vpqc::encryption::open(&keys.secret, &sealed, b\"app/v1\")?;"
        }
        _ => {
            "vpqc_encryption_keygen(VPQC_PROFILE_STANDARD, &pk, &sk);\nvpqc_seal(pk.ptr, pk.len, data, n, aad, m, &sealed);\nvpqc_open(sk.ptr, sk.len, sealed.ptr, sealed.len, aad, m, &plain);"
        }
    }
}

fn sign(lang: &str) -> &'static str {
    match lang {
        "Python" => {
            "keys = vpqc.generate_signing_keypair()\nsig = vpqc.sign(keys.secret, msg, context=b\"app/v1\")\nvpqc.verify(keys.public, msg, sig, context=b\"app/v1\")"
        }
        "JavaScript/TypeScript" => {
            "const keys = vpqc.generateSigningKeypair();\nconst sig = vpqc.sign(keys.secretKey, msg, ctx);\nvpqc.verify(keys.publicKey, msg, ctx, sig);"
        }
        "Go" => {
            "pk, sk, _ := vpqc.GenerateSigningKeypair(vpqc.ProfileStandard)\nsig, _ := vpqc.Sign(sk, msg, []byte(\"app/v1\"))\nerr := vpqc.Verify(pk, msg, []byte(\"app/v1\"), sig)"
        }
        "Java/Kotlin" => {
            "KeyPair keys = Vpqc.generateSigningKeypair(Profile.STANDARD);\nbyte[] sig = Vpqc.sign(keys.secretKey(), msg, ctx);\nVpqc.verify(keys.publicKey(), msg, ctx, sig);"
        }
        "PHP" => {
            "$keys = Vpqc::generateSigningKeypair();\n$sig = Vpqc::sign($keys->secret, $msg, 'app/v1');\nVpqc::verify($keys->public, $msg, 'app/v1', $sig);"
        }
        "Ruby" => {
            "keys = Vpqc.generate_signing_keypair\nsig = Vpqc.sign(keys.secret, msg, context: \"app/v1\")\nVpqc.verify(keys.public, msg, sig, context: \"app/v1\")"
        }
        "C#" => {
            "var keys = Vpqc.GenerateSigningKeypair();\nvar sig = Vpqc.Sign(keys.Secret, msg, ctx);\nVpqc.Verify(keys.Public, msg, ctx, sig);"
        }
        "Dart" => {
            "final keys = Vpqc.generateSigningKeypair();\nfinal sig = Vpqc.sign(keys.secret, msg, context: ctx);\nVpqc.verify(keys.public, msg, sig, context: ctx);"
        }
        "Rust" => {
            "let keys = vpqc::signing::generate(Profile::Standard)?;\nlet sig = vpqc::signing::sign(&keys.secret, msg, b\"app/v1\")?;\nvpqc::signing::verify(&keys.public, msg, b\"app/v1\", &sig)?;"
        }
        _ => {
            "vpqc_signing_keygen(VPQC_PROFILE_STANDARD, &pk, &sk);\nvpqc_sign(sk.ptr, sk.len, msg, n, ctx, m, &sig);\nvpqc_verify(pk.ptr, pk.len, msg, n, ctx, m, sig.ptr, sig.len);"
        }
    }
}

const WEAK_HASH: &str =
    "SHA-256, SHA-384 or SHA-3 instead; for passwords use Argon2id, not a plain hash.";
const CAVEAT_ENCRYPT: &str = "vpqc seals with its own format (hybrid X-Wing + ChaCha20-Poly1305): it does not read RSA-OAEP or ECIES data, so re-encrypt stored data or run both side by side (encrypt to a classical and a vpqc recipient with `vpqc encrypt --to ...`). `aad` must match when opening.";
const CAVEAT_SIGN: &str = "vpqc signatures are composite (Ed25519 + ML-DSA-65) with their own format, and need a domain-separation context. For certificates, JWTs and tokens use `vpqc x509`, `vpqc jwt` or `vpqc cwt`, which follow the standards. Short-lived authentication may stay classical (`fast-auth`).";

/// The suggestion for a finding, or `None` for findings that are not code in a known language
/// (certificates, key files, configuration: their advice text applies) and for non-problems.
pub fn suggest(f: &Finding) -> Option<Suggestion> {
    if f.source != Source::Code {
        return None;
    }
    let lang = language(&f.path)?;
    let (snippets, caveat) = match usage(f)? {
        Use::Encrypt => (
            vec![("key exchange / public-key encryption", encrypt(lang))],
            CAVEAT_ENCRYPT,
        ),
        Use::Sign => (vec![("signatures", sign(lang))], CAVEAT_SIGN),
        Use::Either => (
            vec![
                ("if this is key exchange or encryption", encrypt(lang)),
                ("if this is a signature", sign(lang)),
            ],
            CAVEAT_ENCRYPT,
        ),
        Use::Weak => (Vec::new(), WEAK_HASH),
    };
    Some(Suggestion {
        language: lang,
        snippets,
        caveat,
    })
}

fn problems(report: &Report) -> Vec<&Finding> {
    let mut v: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|f| matches!(f.risk, Risk::QuantumVulnerable | Risk::Weak))
        .collect();
    // Most urgent tier first, then by place.
    v.sort_by(|a, b| (a.tier, &a.path, a.line).cmp(&(b.tier, &b.path, b.line)));
    v
}

/// Human-readable suggestions, most urgent first.
pub fn to_lint_text(report: &Report) -> String {
    let items = problems(report);
    let mut out = String::new();
    if items.is_empty() {
        out.push_str("No quantum-vulnerable or weak algorithms found.\n");
        return out;
    }
    // The same snippet is printed once per file; later findings in that file refer back to it.
    let mut shown: std::collections::HashSet<(&str, &str)> = std::collections::HashSet::new();
    for f in &items {
        let place = match f.line {
            Some(l) => format!("{}:{l}", f.path),
            None => f.path.clone(),
        };
        let _ = writeln!(out, "{place}  {} [{}]", f.algorithm, f.tier);
        let _ = writeln!(out, "  {}", f.detail);
        match suggest(f) {
            Some(s) => {
                for (what, code) in &s.snippets {
                    if shown.insert((f.path.as_str(), code)) {
                        let _ = writeln!(out, "  migrate to vpqc ({}), {what}:", s.language);
                        for line in code.lines() {
                            let _ = writeln!(out, "      {line}");
                        }
                    } else {
                        let _ = writeln!(
                            out,
                            "  migrate to vpqc ({}), {what}: as suggested above in this file",
                            s.language
                        );
                    }
                }
                if shown.insert((f.path.as_str(), s.caveat)) {
                    let _ = writeln!(out, "  note: {}", s.caveat);
                }
            }
            None => {
                let _ = writeln!(out, "  advice: {}", f.advice);
            }
        }
        out.push('\n');
    }
    let _ = writeln!(
        out,
        "{} finding(s). Code detection is pattern-based: check each one. Suggestions are starting points, not drop-in replacements.",
        items.len()
    );
    out
}

/// Machine-readable suggestions.
pub fn to_lint_json(report: &Report) -> String {
    let items: Vec<Value> = problems(report)
        .iter()
        .map(|f| {
            let s = suggest(f);
            json!({
                "path": f.path,
                "line": f.line,
                "algorithm": f.algorithm,
                "tier": f.tier,
                "risk": f.risk.as_str(),
                "detail": f.detail,
                "advice": f.advice,
                "suggestion": s.as_ref().map(|s| json!({
                    "language": s.language,
                    "snippets": s.snippets.iter().map(|(what, code)| json!({ "for": what, "code": code })).collect::<Vec<_>>(),
                    "caveat": s.caveat,
                })),
            })
        })
        .collect();
    serde_json::to_string_pretty(&json!({ "tool": "vpqc-lint", "findings": items }))
        .expect("serializable")
}
