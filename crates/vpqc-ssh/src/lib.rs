//! SSH post-quantum readiness.
//!
//! SSH key exchange is exposed to "harvest now, decrypt later": a recorded session can be
//! decrypted once the (EC)DH exchange is broken. OpenSSH offers hybrid post-quantum key
//! exchanges (`sntrup761x25519-sha512` since 9.0, `mlkem768x25519-sha256` since 9.9 and the
//! default in 10.0), but servers and clients often pin older lists. This crate:
//!
//! * [`probe`] connects to a server and reads its `SSH_MSG_KEXINIT`, which is sent in the clear
//!   before any authentication, and classifies the offered algorithms;
//! * [`audit_kex_directive`] evaluates an OpenSSH `KexAlgorithms` setting as it appears in
//!   `sshd_config` / `ssh_config`.
//!
//! Host keys and user authentication are signatures and only need to resist a quantum computer
//! at the time of the connection, so they are reported but rated lower (ADR-0003).

mod config;
mod kex;
mod probe;

pub use config::{KexAudit, audit_kex_directive};
pub use kex::{KexClass, classify_kex};
pub use probe::{KexInit, ProbeError, ServerOffer, parse_kexinit, probe};
