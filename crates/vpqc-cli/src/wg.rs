//! `vpqc wg`: post-quantum pre-shared keys for WireGuard (ADR-0014).
//!
//! WireGuard mixes an optional 32-byte pre-shared key into its handshake, so a PSK unknown to
//! the adversary keeps the tunnel confidential even if X25519 falls. `psk-seal` draws a random
//! PSK and seals it to the peer's vpqc encryption key (hybrid X-Wing sealed box); `psk-open`
//! recovers it on the peer. No new protocol: an existing sealed box carries an existing
//! WireGuard feature. The associated data binds the PSK to the tunnel (both WireGuard public
//! keys, in either order), so a sealed PSK cannot be replayed for another peer pair.
//!
//! A sealed box does not say who sealed it: anyone can seal a PSK of their choosing to Bob's
//! public key. Over a channel that is not authenticated, the sender should therefore sign
//! (`--sign-key`), and the receiver require the signature (`--from`):
//!
//! ```text
//! signed : "VPQCWGS1" sealed_len:u32 | sealed | signature(context, aad || sealed)
//! ```

use std::path::{Path, PathBuf};

use base64::{Engine, engine::general_purpose::STANDARD};
use clap::Subcommand;
use vpqc::{OsRng, RandomSource, encryption, keys, signing};
use zeroize::Zeroizing;

use crate::{CliResult, read_input, read_key_bytes, secret, write_new, write_output};

const AAD_LABEL: &[u8] = b"vpqc/wireguard-psk/v1";
const SIGNED_MAGIC: &[u8; 8] = b"VPQCWGS1";

#[derive(Subcommand)]
pub enum WgCommand {
    /// Generate a random PSK for a WireGuard peer: write it (WireGuard base64, mode 0600) for
    /// this side, and sealed to the peer's vpqc encryption key for the other side.
    PskSeal {
        /// The peer's vpqc encryption public key.
        #[arg(long)]
        to: PathBuf,
        /// This side's WireGuard public key (base64, as `wg show IFACE public-key` prints).
        #[arg(long)]
        wg_local: String,
        /// The peer's WireGuard public key (base64).
        #[arg(long)]
        wg_peer: String,
        /// File for this side's copy of the PSK (for `wg set IFACE peer KEY preshared-key FILE`).
        #[arg(long)]
        psk_out: PathBuf,
        /// Sign the sealed PSK with this vpqc signing key, so the peer can check who sent it
        /// (recommended unless the delivery channel is authenticated).
        #[arg(long)]
        sign_key: Option<PathBuf>,
        /// Write base64 text instead of binary for the sealed PSK.
        #[arg(long)]
        base64: bool,
        /// Sealed PSK output for the peer (default: stdout).
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Overwrite existing files (key rotation).
        #[arg(long)]
        force: bool,
    },
    /// Recover a sealed PSK with this side's vpqc secret key and write it in WireGuard format.
    PskOpen {
        /// This side's vpqc secret key (plain or protected).
        #[arg(long)]
        key: PathBuf,
        /// This side's WireGuard public key (base64).
        #[arg(long)]
        wg_local: String,
        /// The peer's WireGuard public key (base64).
        #[arg(long)]
        wg_peer: String,
        /// Require a signature by this vpqc signing public key (the sender's).
        #[arg(long)]
        from: Option<PathBuf>,
        /// PSK output file (mode 0600).
        #[arg(short, long)]
        output: PathBuf,
        /// Overwrite an existing file (key rotation).
        #[arg(long)]
        force: bool,
        /// Sealed PSK (binary or base64 text; default: stdin).
        input: Option<PathBuf>,
    },
}

fn wg_key(text: &str, what: &str) -> Result<[u8; 32], String> {
    STANDARD
        .decode(text.trim())
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
        .ok_or_else(|| format!("{what}: not a WireGuard key (32 bytes, base64)"))
}

/// `label || min(a, b) || max(a, b)`: the same on both sides of the tunnel.
fn aad(local: &str, peer: &str) -> Result<Vec<u8>, String> {
    let (a, b) = (wg_key(local, "--wg-local")?, wg_key(peer, "--wg-peer")?);
    if a == b {
        return Err("--wg-local and --wg-peer must differ".into());
    }
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    Ok([AAD_LABEL, &lo, &hi].concat())
}

fn write_psk(path: &Path, psk: &[u8], force: bool) -> CliResult {
    let text = Zeroizing::new(format!("{}\n", STANDARD.encode(psk)));
    write_new(path, text.as_bytes(), true, force)
}

pub fn run(cmd: WgCommand) -> CliResult {
    match cmd {
        WgCommand::PskSeal {
            to,
            wg_local,
            wg_peer,
            psk_out,
            sign_key,
            base64,
            output,
            force,
        } => {
            let aad = aad(&wg_local, &wg_peer)?;
            let pk = keys::public_from_bytes(&read_key_bytes(&to, "VPQC PUBLIC KEY")?)
                .map_err(|e| format!("{}: {e}", to.display()))?;
            let mut psk = Zeroizing::new([0u8; 32]);
            OsRng.fill(&mut *psk).map_err(|e| e.to_string())?;
            let mut sealed = encryption::seal(&pk, &*psk, &aad).map_err(|e| e.to_string())?;
            if let Some(path) = sign_key {
                let sk = secret::load(&path)?;
                let sig = signing::sign(&sk, &[aad.as_slice(), &sealed].concat(), AAD_LABEL)
                    .map_err(|e| format!("{}: {e}", path.display()))?;
                let mut out = SIGNED_MAGIC.to_vec();
                out.extend_from_slice(&(sealed.len() as u32).to_be_bytes());
                out.extend_from_slice(&sealed);
                out.extend_from_slice(&sig);
                sealed = out;
            }
            write_psk(&psk_out, &*psk, force)?;
            if base64 {
                write_output(
                    &output,
                    format!("{}\n", STANDARD.encode(&sealed)).as_bytes(),
                )
            } else {
                write_output(&output, &sealed)
            }
        }
        WgCommand::PskOpen {
            key,
            wg_local,
            wg_peer,
            from,
            output,
            force,
            input,
        } => {
            let aad = aad(&wg_local, &wg_peer)?;
            let sk = secret::load(&key)?;
            let raw = read_input(&input)?;
            let sealed = match std::str::from_utf8(&raw) {
                Ok(t)
                    if t.trim()
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b)) =>
                {
                    STANDARD
                        .decode(t.trim())
                        .map_err(|_| "input is not valid base64")?
                }
                _ => raw,
            };
            let sealed = match (sealed.strip_prefix(SIGNED_MAGIC), from) {
                (Some(rest), Some(from)) => {
                    let pk = keys::public_from_bytes(&read_key_bytes(&from, "VPQC PUBLIC KEY")?)
                        .map_err(|e| format!("{}: {e}", from.display()))?;
                    let len = rest
                        .get(..4)
                        .map(|b| u32::from_be_bytes(b.try_into().expect("4 bytes")) as usize)
                        .filter(|&n| n <= rest.len() - 4)
                        .ok_or("malformed signed PSK")?;
                    let (body, sig) = rest[4..].split_at(len);
                    signing::verify(&pk, &[aad.as_slice(), body].concat(), AAD_LABEL, sig)
                        .map_err(|_| "the PSK is not signed by --from")?;
                    body.to_vec()
                }
                (Some(_), None) => {
                    return Err("the PSK is signed: pass the sender's key with --from".into());
                }
                (None, Some(_)) => {
                    return Err("the PSK is not signed, but --from requires it".into());
                }
                (None, None) => sealed,
            };
            let psk = Zeroizing::new(encryption::open(&sk, &sealed, &aad).map_err(|e| {
                match e {
                vpqc::Error::DecryptionFailed => {
                    "cannot open the sealed PSK: wrong key, wrong WireGuard keys, or modified data"
                        .to_string()
                }
                e => e.to_string(),
            }
            })?);
            if psk.len() != 32 {
                return Err("sealed data is not a WireGuard PSK".into());
            }
            write_psk(&output, &psk, force)
        }
    }
}
