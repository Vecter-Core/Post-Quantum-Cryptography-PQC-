//! Report rendering: text, JSON and CycloneDX 1.6 CBOM.

use std::collections::BTreeMap;
use std::fmt::Write;

use serde_json::{Value, json};

use crate::model::{Family, Finding, Purpose, Report, Risk, Source};

/// Human-readable report, most urgent first. Informational findings are shown only if `all`.
pub fn to_text(report: &Report, all: bool) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "vpqc scan: {} files scanned, {} skipped, {} findings\n",
        report.files_scanned,
        report.files_skipped,
        report.findings.len()
    );
    let order = [
        Risk::QuantumVulnerable,
        Risk::Weak,
        Risk::PostQuantum,
        Risk::Info,
    ];
    for risk in order {
        if risk == Risk::Info && !all {
            continue;
        }
        let items: Vec<_> = report.findings.iter().filter(|f| f.risk == risk).collect();
        if items.is_empty() {
            continue;
        }
        let title = match risk {
            Risk::QuantumVulnerable => "QUANTUM-VULNERABLE",
            Risk::Weak => "WEAK / OBSOLETE",
            Risk::PostQuantum => "POST-QUANTUM (good)",
            Risk::Info => "INFORMATIONAL",
        };
        let _ = writeln!(out, "== {title} ({}) ==", items.len());
        // Group by (tier, algorithm) so a large tree stays readable; JSON has every location.
        let mut groups: BTreeMap<(&str, &str), Vec<&Finding>> = BTreeMap::new();
        for f in items {
            groups
                .entry((f.tier, f.algorithm.as_str()))
                .or_default()
                .push(f);
        }
        for ((tier, algorithm), members) in groups {
            let first = |f: &Finding| match f.line {
                Some(l) => format!("{}:{l}", f.path),
                None => f.path.clone(),
            };
            let shown: Vec<String> = members.iter().take(3).map(|f| first(f)).collect();
            let more = members.len().saturating_sub(3);
            let _ = writeln!(
                out,
                "  [{tier:<5}] {algorithm:<30} x{:<4} {}{}",
                members.len(),
                shown.join(", "),
                if more > 0 {
                    format!(", +{more} more")
                } else {
                    String::new()
                }
            );
            if members.iter().any(|f| f.long_lived) {
                let _ = writeln!(
                    out,
                    "          includes long-lived certificates (valid past 2030)"
                );
            }
        }
        let _ = writeln!(out);
    }
    let mut advice: BTreeMap<&str, &str> = BTreeMap::new();
    for f in &report.findings {
        if f.risk >= Risk::Weak || f.risk == Risk::PostQuantum {
            advice.entry(f.tier).or_insert(f.advice);
        }
    }
    if !advice.is_empty() {
        let _ = writeln!(out, "What to do:");
        for (tier, text) in advice {
            let _ = writeln!(out, "  {tier:<6} {text}");
        }
    }
    let _ = writeln!(
        out,
        "\nNote: code and config detection is pattern-based (mentions, not proof of use). \
         Certificates and key files are parsed exactly."
    );
    out
}

fn finding_json(f: &Finding) -> Value {
    json!({
        "path": f.path,
        "line": f.line,
        "source": f.source.as_str(),
        "algorithm": f.algorithm,
        "risk": f.risk.as_str(),
        "tier": f.tier,
        "longLived": f.long_lived,
        "detail": f.detail,
        "advice": f.advice,
    })
}

/// Machine-readable report (vpqc scan format).
pub fn to_json(report: &Report) -> String {
    let doc = json!({
        "tool": "vpqc-scan",
        "filesScanned": report.files_scanned,
        "filesSkipped": report.files_skipped,
        "summary": {
            "quantumVulnerable": report.count(Risk::QuantumVulnerable),
            "weak": report.count(Risk::Weak),
            "postQuantum": report.count(Risk::PostQuantum),
            "info": report.count(Risk::Info),
        },
        "findings": report.findings.iter().map(finding_json).collect::<Vec<_>>(),
    });
    serde_json::to_string_pretty(&doc).expect("serializable")
}

/// CycloneDX primitive and key facts for a family.
fn crypto_facts(f: &Finding) -> (&'static str, Option<u32>, Option<u32>, Vec<&'static str>) {
    // (primitive, classical security bits, NIST quantum security level, functions)
    match f.family {
        Family::Rsa => (
            "pke",
            None,
            Some(0),
            vec!["encrypt", "decrypt", "sign", "verify"],
        ),
        Family::Dsa | Family::Ecdsa | Family::EdDsa => {
            ("signature", None, Some(0), vec!["sign", "verify"])
        }
        Family::Ecc => ("other", None, Some(0), vec!["other"]),
        Family::Ecdh | Family::Dh | Family::X25519 => {
            ("key-agree", None, Some(0), vec!["keyderive"])
        }
        Family::Aes128 => (
            "block-cipher",
            Some(128),
            Some(1),
            vec!["encrypt", "decrypt"],
        ),
        Family::Aes256 => (
            "block-cipher",
            Some(256),
            Some(5),
            vec!["encrypt", "decrypt"],
        ),
        Family::ChaCha20 => (
            "stream-cipher",
            Some(256),
            Some(5),
            vec!["encrypt", "decrypt"],
        ),
        Family::BrokenHash => ("hash", None, None, vec!["digest"]),
        Family::BrokenCipher => ("block-cipher", None, None, vec!["encrypt", "decrypt"]),
        Family::LegacyProtocol => ("other", None, None, vec!["other"]),
        Family::PqKem => ("kem", None, Some(3), vec!["encapsulate", "decapsulate"]),
        Family::HybridKem => ("kem", None, Some(3), vec!["encapsulate", "decapsulate"]),
        Family::PqSignature => ("signature", None, Some(3), vec!["sign", "verify"]),
    }
}

fn bom_ref(f: &Finding, index: usize) -> String {
    let base: String = f
        .algorithm
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    format!("crypto/{}/{base}@{index}", f.source.as_str())
}

/// CycloneDX 1.6 CBOM (cryptographic bill of materials). Algorithm components are merged by
/// algorithm name; each occurrence records the file and line. Certificates and key files become
/// their own assets.
pub fn to_cbom(report: &Report) -> String {
    let mut components: Vec<Value> = Vec::new();
    let mut algorithm_index: BTreeMap<String, usize> = BTreeMap::new();

    for (i, f) in report.findings.iter().enumerate() {
        let occurrence = match f.line {
            Some(l) => json!({ "location": f.path, "line": l }),
            None => json!({ "location": f.path }),
        };
        let properties = |f: &Finding| {
            json!([
                { "name": "vpqc:risk", "value": f.risk.as_str() },
                { "name": "vpqc:tier", "value": f.tier },
                { "name": "vpqc:advice", "value": f.advice },
            ])
        };
        match f.source {
            Source::Certificate | Source::PublicKey | Source::PrivateKey => {
                let (asset_type, extra) = match f.source {
                    Source::Certificate => (
                        "certificate",
                        json!({ "certificateProperties": { "certificateFormat": "X.509" } }),
                    ),
                    _ => (
                        "related-crypto-material",
                        json!({ "relatedCryptoMaterialProperties": {
                            "type": if f.source == Source::PrivateKey { "private-key" } else { "public-key" }
                        } }),
                    ),
                };
                let mut crypto = json!({ "assetType": asset_type });
                crypto
                    .as_object_mut()
                    .expect("object")
                    .extend(extra.as_object().expect("object").clone());
                components.push(json!({
                    "type": "cryptographic-asset",
                    "bom-ref": bom_ref(f, i),
                    "name": f.algorithm,
                    "description": f.detail,
                    "cryptoProperties": crypto,
                    "evidence": { "occurrences": [occurrence] },
                    "properties": properties(f),
                }));
            }
            Source::Code => {
                let key = f.algorithm.clone();
                if let Some(&idx) = algorithm_index.get(&key) {
                    components[idx]["evidence"]["occurrences"]
                        .as_array_mut()
                        .expect("array")
                        .push(occurrence);
                } else {
                    let (primitive, classical, quantum, functions) = crypto_facts(f);
                    let mut algo = json!({ "primitive": primitive, "cryptoFunctions": functions });
                    if let Some(c) = classical {
                        algo["classicalSecurityLevel"] = json!(c);
                    }
                    if let Some(q) = quantum {
                        algo["nistQuantumSecurityLevel"] = json!(q);
                    }
                    algorithm_index.insert(key, components.len());
                    components.push(json!({
                        "type": "cryptographic-asset",
                        "bom-ref": bom_ref(f, i),
                        "name": f.algorithm,
                        "cryptoProperties": { "assetType": "algorithm", "algorithmProperties": algo },
                        "evidence": { "occurrences": [occurrence] },
                        "properties": properties(f),
                    }));
                }
            }
        }
    }

    let _ = Purpose::Other; // purposes are folded into the vpqc:tier property
    let doc = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "tools": { "components": [{
                "type": "application",
                "name": "vpqc-scan",
                "version": env!("CARGO_PKG_VERSION"),
            }] },
            "properties": [
                { "name": "vpqc:note", "value": "Pattern-based inventory: mentions of algorithms, not proof of use." }
            ]
        },
        "components": components,
    });
    serde_json::to_string_pretty(&doc).expect("serializable")
}
