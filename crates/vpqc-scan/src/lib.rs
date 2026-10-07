//! Cryptographic inventory scanner.
//!
//! Walks a directory tree and reports quantum-vulnerable algorithms found in source code,
//! configuration files and X.509 certificates / key files, ranked by migration priority, with
//! a recommended vpqc profile. Output can be plain text, JSON or a CycloneDX 1.6 CBOM
//! (cryptographic bill of materials).
//!
//! **Source and config detection is pattern-based and heuristic**: it finds *mentions* of
//! algorithms, not proof of use, and can produce both false positives (an algorithm name in a
//! comment) and false negatives (crypto hidden behind a wrapper). Certificates and key files
//! are parsed properly. Key material is never printed or stored.

mod certs;
mod lint;
mod model;
mod output;
mod rules;
mod vpn;
mod walk;

pub use lint::{Suggestion, Use, suggest, to_lint_json, to_lint_text};
pub use model::{Family, Finding, Purpose, Report, Risk, Source};
pub use output::{to_cbom, to_json, to_sarif, to_text};
pub use walk::{Options, scan_bytes, scan_path};
