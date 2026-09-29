//! `vpqc ssh probe`: does an SSH server offer a post-quantum key exchange?

use std::time::Duration;

use clap::Subcommand;
use vpqc_ssh::{KexClass, classify_kex, probe};

use crate::CliResult;

#[derive(Subcommand)]
pub enum SshCommand {
    /// Read a server's key exchange offer (no authentication, nothing is logged in) and report
    /// whether it offers a hybrid post-quantum key exchange. Exit code 2 with --require-pq if
    /// it does not.
    Probe {
        /// host, host:port, [ipv6]:port (port 22 by default).
        address: String,
        /// Exit with status 2 unless a post-quantum hybrid key exchange is offered.
        #[arg(long)]
        require_pq: bool,
        /// Print JSON.
        #[arg(long)]
        json: bool,
        /// Timeout in seconds for the connection and each read.
        #[arg(long, default_value_t = 10)]
        timeout: u64,
    },
}

fn label(class: KexClass) -> &'static str {
    match class {
        KexClass::HybridMlKem => "post-quantum hybrid (ML-KEM)",
        KexClass::HybridSntrup => "post-quantum hybrid (sntrup761, not NIST)",
        KexClass::Classical => "classical: quantum-vulnerable",
        KexClass::Weak => "WEAK (SHA-1 or small group)",
        KexClass::Marker => "extension marker",
        KexClass::Unknown => "unknown",
    }
}

pub fn run(cmd: SshCommand) -> CliResult {
    let SshCommand::Probe {
        address,
        require_pq,
        json,
        timeout,
    } = cmd;
    let offer = probe(&address, Duration::from_secs(timeout.max(1)))
        .map_err(|e| format!("{address}: {e}"))?;
    let pq = offer.post_quantum_kex();
    if json {
        let kex: Vec<serde_json::Value> = offer
            .kexinit
            .kex
            .iter()
            .map(|k| serde_json::json!({ "name": k, "class": format!("{:?}", classify_kex(k)) }))
            .collect();
        println!(
            "{}",
            serde_json::json!({
                "address": address,
                "identification": offer.identification,
                "kex": kex,
                "post_quantum": !pq.is_empty(),
                "ml_kem": offer.offers_ml_kem(),
                "strict_kex": offer.strict_kex(),
                "host_keys": offer.kexinit.host_keys,
            })
        );
    } else {
        println!("server      : {}", offer.identification);
        println!("key exchange (server preference order):");
        for k in &offer.kexinit.kex {
            println!("  {k:<44} {}", label(classify_kex(k)));
        }
        println!(
            "host keys   : {} (signatures: classical, lower priority)",
            offer.kexinit.host_keys.join(", ")
        );
        println!(
            "strict KEX  : {}",
            if offer.strict_kex() {
                "yes"
            } else {
                "NO (Terrapin CVE-2023-48795 not mitigated)"
            }
        );
        match (pq.is_empty(), offer.offers_ml_kem()) {
            (true, _) => println!(
                "verdict     : NO post-quantum key exchange: recorded sessions can be decrypted later.\n              Upgrade to OpenSSH >= 9.9 (mlkem768x25519-sha256) or enable it in KexAlgorithms."
            ),
            (false, true) => println!(
                "verdict     : post-quantum hybrid offered (ML-KEM); clients need OpenSSH >= 9.9 to use it"
            ),
            (false, false) => println!(
                "verdict     : post-quantum hybrid offered (sntrup761 only); prefer mlkem768x25519-sha256 (OpenSSH >= 9.9)"
            ),
        }
    }
    if require_pq && pq.is_empty() {
        std::process::exit(2);
    }
    Ok(())
}
