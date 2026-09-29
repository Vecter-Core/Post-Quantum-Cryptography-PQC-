//! VPN configuration audit (ADR-0014): WireGuard peers without a pre-shared key, and
//! strongSwan IKEv2/ESP proposals without ML-KEM (RFC 9370 additional key exchanges).
//!
//! Key material in these files (`PrivateKey`, `PresharedKey`, ...) is never copied into a
//! finding; the lines are blanked before the generic text rules run.

use std::path::Path;

use crate::model::{Family, Finding, Purpose, Source, classify};

const WG_ADVICE: &str = "WireGuard's X25519 handshake is exposed to harvest-now-decrypt-later: add a PresharedKey per peer that a quantum computer cannot learn (distribute it sealed with a post-quantum key, `vpqc wg psk-seal`, or rotate it with Rosenpass), and rotate it regularly.";
const WG_PSK_NOTE: &str = "The pre-shared key protects the tunnel against a quantum adversary only if it was distributed out of band or over a post-quantum channel (vpqc wg psk-seal, Rosenpass) and is rotated.";
const IKE_ADVICE: &str = "Add an ML-KEM additional key exchange (RFC 9370) to the proposal, e.g. aes256gcm16-prfsha384-x25519-ke1_mlkem768 (strongSwan >= 6.0), keeping the classical group first for a hybrid exchange.";

/// Which VPN configuration dialect a file uses, if any.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Dialect {
    /// wg-quick / `wg setconf`: `[Interface]`, `[Peer]`, `PresharedKey`.
    WireGuard,
    /// systemd-networkd `.netdev`: `[WireGuardPeer]`, `PresharedKey` / `PresharedKeyFile`.
    Networkd,
    /// NetworkManager keyfile: `[wireguard-peer.<key>]`, `preshared-key`.
    NetworkManager,
    /// strongSwan `swanctl.conf` / `ipsec.conf`.
    StrongSwan,
}

fn section(line: &str) -> Option<&str> {
    let t = line.trim();
    t.strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .map(str::trim)
}

fn key(line: &str) -> Option<String> {
    let t = line.trim();
    if t.starts_with('#') || t.starts_with(';') {
        return None;
    }
    t.split_once('=')
        .map(|(k, _)| k.trim().to_ascii_lowercase())
}

pub(crate) fn dialect(display: &str, text: &str) -> Option<Dialect> {
    let p = Path::new(display);
    let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let sections: Vec<&str> = text.lines().filter_map(section).collect();
    let has = |s: &str| sections.iter().any(|x| x.eq_ignore_ascii_case(s));
    if has("WireGuardPeer") || (has("WireGuard") && name.ends_with(".netdev")) {
        return Some(Dialect::Networkd);
    }
    if sections.iter().any(|s| s.starts_with("wireguard-peer.")) {
        return Some(Dialect::NetworkManager);
    }
    if has("Interface") && (has("Peer") || text.to_ascii_lowercase().contains("privatekey")) {
        return Some(Dialect::WireGuard);
    }
    let in_swan_dir = display.contains("swanctl") || display.contains("strongswan");
    if name == "swanctl.conf" || name == "ipsec.conf" || (in_swan_dir && name.ends_with(".conf")) {
        return Some(Dialect::StrongSwan);
    }
    None
}

fn finding(
    path: &str,
    line: usize,
    family: Family,
    algorithm: &str,
    detail: String,
    advice: &'static str,
) -> Finding {
    let (risk, tier, default_advice) = classify(family, Purpose::KeyExchange, false);
    Finding {
        path: path.to_string(),
        line: Some(line),
        source: Source::Code,
        algorithm: algorithm.to_string(),
        family,
        purpose: Purpose::KeyExchange,
        risk,
        tier,
        detail,
        advice: if family == Family::HybridKem {
            default_advice
        } else {
            advice
        },
        long_lived: false,
    }
}

/// Audit the file; returns the text with key-bearing and audited lines blanked, for the
/// generic rules.
pub(crate) fn scan(path: &str, text: &str, dialect: Dialect, out: &mut Vec<Finding>) -> String {
    match dialect {
        Dialect::StrongSwan => scan_strongswan(path, text, out),
        _ => scan_wireguard(path, text, dialect, out),
    }
}

fn scan_wireguard(path: &str, text: &str, dialect: Dialect, out: &mut Vec<Finding>) -> String {
    let is_peer = |s: &str| match dialect {
        Dialect::WireGuard => s.eq_ignore_ascii_case("Peer"),
        Dialect::Networkd => s.eq_ignore_ascii_case("WireGuardPeer"),
        _ => s.starts_with("wireguard-peer."),
    };
    let psk_key = |k: &str| matches!(k, "presharedkey" | "presharedkeyfile" | "preshared-key");
    // (line of the [Peer] header, has a pre-shared key)
    let mut peers: Vec<(usize, bool)> = Vec::new();
    let mut in_peer = false;
    let mut rest = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if let Some(s) = section(line) {
            in_peer = is_peer(s);
            if in_peer {
                peers.push((i + 1, false));
            }
            rest.push(line);
            continue;
        }
        match key(line) {
            Some(k) if in_peer && psk_key(&k) => {
                // An empty value (`PresharedKey =`) means no key.
                let value = line.split_once('=').map(|(_, v)| v.trim()).unwrap_or("");
                if !value.is_empty()
                    && let Some(p) = peers.last_mut()
                {
                    p.1 = true;
                }
                rest.push("");
            }
            Some(k) if k.contains("key") => rest.push(""),
            _ => rest.push(line),
        }
    }
    for (line, psk) in peers {
        out.push(if psk {
            finding(
                path,
                line,
                Family::HybridKem,
                "WireGuard peer with pre-shared key (X25519 + PSK)",
                WG_PSK_NOTE.to_string(),
                WG_ADVICE,
            )
        } else {
            finding(
                path,
                line,
                Family::X25519,
                "WireGuard peer without pre-shared key (X25519 only)",
                "no PresharedKey: the tunnel's confidentiality rests on X25519 alone".to_string(),
                WG_ADVICE,
            )
        });
    }
    rest.join("\n")
}

/// Classical key-exchange tokens of strongSwan proposals.
fn classical_group(token: &str) -> bool {
    let t = token.strip_prefix("ke").map_or(token, |r| {
        r.split_once('_').map_or(token, |(n, g)| {
            if n.chars().all(|c| c.is_ascii_digit()) {
                g
            } else {
                token
            }
        })
    });
    t.starts_with("modp")
        || t.starts_with("ecp")
        || t.starts_with("brainpool")
        || matches!(t, "curve25519" | "x25519" | "curve448" | "x448")
}

fn pq_group(token: &str) -> bool {
    token.contains("mlkem")
}

fn scan_strongswan(path: &str, text: &str, out: &mut Vec<Finding>) -> String {
    let mut rest = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let k = key(line).unwrap_or_default();
        let is_proposal = matches!(
            k.as_str(),
            "proposals" | "esp_proposals" | "ah_proposals" | "ike" | "esp"
        );
        if !is_proposal {
            rest.push(line);
            continue;
        }
        rest.push("");
        let value = line.split_once('=').map(|(_, v)| v.trim()).unwrap_or("");
        let proposals: Vec<&str> = value
            .split(',')
            .map(|p| p.trim().trim_end_matches('!'))
            .filter(|p| !p.is_empty() && *p != "default")
            .collect();
        let tokens = |p: &&str| {
            p.split('-')
                .map(str::to_ascii_lowercase)
                .collect::<Vec<_>>()
        };
        let with_ke: Vec<Vec<String>> = proposals
            .iter()
            .map(tokens)
            .filter(|t| t.iter().any(|x| classical_group(x) || pq_group(x)))
            .collect();
        if with_ke.is_empty() {
            continue; // no key exchange named (defaults, or ESP without PFS)
        }
        let pq = with_ke
            .iter()
            .filter(|t| t.iter().any(|x| pq_group(x)))
            .count();
        let what = if k.contains("esp") || k == "ah_proposals" {
            "IPsec ESP/AH (CHILD_SA rekey)"
        } else {
            "IKEv2"
        };
        if pq == with_ke.len() {
            let hybrid = with_ke.iter().all(|t| t.iter().any(|x| classical_group(x)));
            out.push(finding(
                path,
                i + 1,
                if hybrid {
                    Family::HybridKem
                } else {
                    Family::PqKem
                },
                &format!(
                    "{what} key exchange with ML-KEM{}",
                    if hybrid { " (hybrid, RFC 9370)" } else { "" }
                ),
                value.to_string(),
                IKE_ADVICE,
            ));
        } else {
            out.push(finding(
                path,
                i + 1,
                Family::Dh,
                &format!("{what} key exchange without ML-KEM"),
                if pq == 0 {
                    format!("{k}: only classical groups")
                } else {
                    format!(
                        "{k}: {} of {} proposals lack ML-KEM, and a peer may choose them",
                        with_ke.len() - pq,
                        with_ke.len()
                    )
                },
                IKE_ADVICE,
            ));
        }
    }
    rest.join("\n")
}
