//! Directory walking and per-file dispatch.

use std::fs;
use std::io::Read;
use std::path::Path;

use crate::certs;
use crate::model::{Finding, Report, Source, classify};
use crate::rules::{hybrid_marker, rules};

/// Scan options.
#[derive(Debug, Clone)]
pub struct Options {
    /// Also scan documentation files (`.md`, `.txt`, `.rst`, ...). Off by default: prose is
    /// full of algorithm names that are not usage.
    pub include_docs: bool,
    /// Also report mentions inside comment lines (`//`, `#`, `/*`, `*`, `--`, `<!--`). Off by
    /// default: a name in a comment is documentation, not usage.
    pub include_comments: bool,
    /// Skip any path containing one of these substrings.
    pub exclude: Vec<String>,
    /// Maximum file size to read, in bytes.
    pub max_file_size: u64,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            include_docs: false,
            include_comments: false,
            exclude: Vec::new(),
            max_file_size: 1 << 20,
        }
    }
}

const SKIP_DIRS: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "target",
    "vendor",
    "dist",
    "build",
    "__pycache__",
    ".venv",
    "venv",
    ".tox",
    ".mypy_cache",
    ".gradle",
    ".idea",
    ".next",
];

const BINARY_EXT: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "webp", "ico", "pdf", "zip", "gz", "tgz", "xz", "bz2", "7z",
    "jar", "war", "class", "so", "dylib", "dll", "exe", "o", "a", "wasm", "woff", "woff2", "ttf",
    "eot", "mp3", "mp4", "mov", "bin", "pyc", "lock",
];

const DOC_EXT: &[&str] = &["md", "markdown", "txt", "rst", "adoc"];

fn ext(path: &Path) -> String {
    path.extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
}

/// Scan a file or directory tree.
pub fn scan_path(root: &Path, options: &Options) -> std::io::Result<Report> {
    let mut report = Report::default();
    walk(root, options, &mut report)?;
    Ok(report)
}

fn walk(path: &Path, options: &Options, report: &mut Report) -> std::io::Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        return Ok(()); // never follow symlinks
    }
    if meta.is_dir() {
        let mut entries: Vec<_> = fs::read_dir(path)?.filter_map(Result::ok).collect();
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let p = entry.path();
            let shown = p.to_string_lossy();
            if options.exclude.iter().any(|x| shown.contains(x.as_str())) {
                continue;
            }
            if p.is_dir() && SKIP_DIRS.contains(&name.as_ref()) {
                continue;
            }
            // Ignore errors on individual entries (permissions, races) and keep going.
            let _ = walk(&p, options, report);
        }
    } else if meta.is_file() {
        scan_file(path, meta.len(), options, report);
    }
    Ok(())
}

fn scan_file(path: &Path, size: u64, options: &Options, report: &mut Report) {
    let e = ext(path);
    if size == 0 || size > options.max_file_size || BINARY_EXT.contains(&e.as_str()) {
        report.files_skipped += 1;
        return;
    }
    if !options.include_docs && DOC_EXT.contains(&e.as_str()) {
        report.files_skipped += 1;
        return;
    }
    let mut bytes = Vec::new();
    match fs::File::open(path).and_then(|mut f| f.read_to_end(&mut bytes)) {
        Ok(_) => {}
        Err(_) => {
            report.files_skipped += 1;
            return;
        }
    }
    let display = path.to_string_lossy().to_string();
    analyse_bytes(&display, &e, &bytes, options, report);
}

/// Scan content held in memory as if it were a file named `name` (the extension selects DER
/// certificate parsing and PEM handling). Size and documentation filters do not apply.
pub fn scan_bytes(name: &str, bytes: &[u8], options: &Options) -> Report {
    let mut report = Report::default();
    let e = ext(Path::new(name));
    analyse_bytes(name, &e, bytes, options, &mut report);
    report
}

fn analyse_bytes(display: &str, e: &str, bytes: &[u8], options: &Options, report: &mut Report) {
    // Binary DER certificates.
    if matches!(e, "der" | "cer" | "crt") && !bytes.starts_with(b"-----") {
        if certs::analyse_der(display, bytes, &mut report.findings) {
            report.files_scanned += 1;
        } else {
            report.files_skipped += 1;
        }
        return;
    }
    if bytes.is_empty() || bytes[..bytes.len().min(8192)].contains(&0) {
        report.files_skipped += 1;
        return;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        report.files_skipped += 1;
        return;
    };
    report.files_scanned += 1;

    if text.contains("-----BEGIN ") || text.contains("ssh-") || text.contains("ecdsa-sha2-") {
        certs::analyse_pem_text(display, text, &mut report.findings);
    }
    // Do not run the text rules over base64 key blocks: they only produce noise.
    if text.contains("-----BEGIN ") && matches!(e, "pem" | "crt" | "cer" | "key" | "pub") {
        return;
    }
    if let Some(dialect) = crate::vpn::dialect(display, text) {
        let rest = crate::vpn::scan(display, text, dialect, &mut report.findings);
        scan_text(
            display,
            &rest,
            options.include_comments,
            &mut report.findings,
        );
        return;
    }
    if is_ssh_config(display) {
        let rest = scan_ssh_config(display, text, &mut report.findings);
        scan_text(
            display,
            &rest,
            options.include_comments,
            &mut report.findings,
        );
        return;
    }
    scan_text(
        display,
        text,
        options.include_comments,
        &mut report.findings,
    );
}

/// OpenSSH client and server configuration files.
fn is_ssh_config(display: &str) -> bool {
    let p = Path::new(display);
    let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let dir = p
        .parent()
        .and_then(|d| d.file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("");
    matches!(name, "sshd_config" | "ssh_config")
        || (matches!(dir, "sshd_config.d" | "ssh_config.d") && name.ends_with(".conf"))
}

const SSH_KEX_ADVICE: &str = "SSH key exchange is exposed to harvest-now-decrypt-later: remove the KexAlgorithms line to use the defaults (hybrid since OpenSSH 9.0), or put mlkem768x25519-sha256 (OpenSSH >= 9.9; older sshd refuses to start with it, run sshd -t) or sntrup761x25519-sha512@openssh.com (>= 9.0) first.";

/// Audit `KexAlgorithms` lines; returns the text with those lines blanked so that the generic
/// rules do not report the same algorithms again.
fn scan_ssh_config(path: &str, text: &str, out: &mut Vec<Finding>) -> String {
    use crate::model::{Family, Purpose};
    use vpqc_ssh::{KexAudit, audit_kex_directive};
    let client = !path.contains("sshd_config");
    let mut rest = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let t = line.trim_start();
        let keyword_len = "kexalgorithms".len();
        // `get`: the line may have a multi-byte character across the keyword length.
        let is_kex = t.len() > keyword_len
            && t.get(..keyword_len)
                .is_some_and(|k| k.eq_ignore_ascii_case("kexalgorithms"))
            && t[keyword_len..].starts_with(|c: char| c.is_ascii_whitespace() || c == '=');
        if !is_kex {
            rest.push(line);
            continue;
        }
        rest.push("");
        let value =
            t[keyword_len..].trim_start_matches(|c: char| c.is_ascii_whitespace() || c == '=');
        let (family, algorithm, detail) = match audit_kex_directive(value) {
            KexAudit::KeepsDefault => continue,
            KexAudit::ClassicalOnly { list } => (
                Family::Ecdh,
                "SSH key exchange without post-quantum hybrid",
                format!(
                    "KexAlgorithms lists only classical key exchanges: {}",
                    list.join(",")
                ),
            ),
            KexAudit::RemovesPostQuantum { removed } => (
                Family::Ecdh,
                "SSH key exchange without post-quantum hybrid",
                format!(
                    "KexAlgorithms -{} removes every post-quantum hybrid from the defaults",
                    removed.join(",")
                ),
            ),
            KexAudit::PostQuantum { pq, pq_first } => (
                Family::HybridKem,
                "SSH hybrid post-quantum key exchange",
                if client && !pq_first {
                    format!(
                        "{} enabled but not first: this client prefers a classical exchange when the server offers it",
                        pq.join(",")
                    )
                } else {
                    format!("{} enabled", pq.join(","))
                },
            ),
        };
        let (risk, tier, advice) = classify(family, Purpose::KeyExchange, false);
        out.push(Finding {
            path: path.to_string(),
            line: Some(i + 1),
            source: Source::Code,
            algorithm: algorithm.to_string(),
            family,
            purpose: Purpose::KeyExchange,
            risk,
            tier,
            detail,
            advice: if family == Family::HybridKem {
                advice
            } else {
                SSH_KEX_ADVICE
            },
            long_lived: false,
        });
    }
    rest.join("\n")
}

fn is_comment(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("//")
        || t.starts_with('#')
        || t.starts_with("/*")
        || t.starts_with('*')
        || t.starts_with("--")
        || t.starts_with("<!--")
}

fn scan_text(path: &str, text: &str, include_comments: bool, out: &mut Vec<Finding>) {
    for (i, line) in text.lines().enumerate() {
        if line.len() > 2000 {
            continue; // minified / generated content
        }
        if !include_comments && is_comment(line) {
            continue;
        }
        let hybrid_line = hybrid_marker().is_match(line);
        let mut seen_families = Vec::new();
        for rule in rules() {
            if seen_families.contains(&rule.family) {
                continue;
            }
            // A hybrid or PQ mention already explains classical components on the same line.
            if hybrid_line
                && matches!(
                    rule.family,
                    crate::Family::X25519
                        | crate::Family::Ecdh
                        | crate::Family::PqKem
                        | crate::Family::Ecc
                )
            {
                continue;
            }
            if let Some(m) = rule.regex.find(line) {
                seen_families.push(rule.family);
                let (risk, tier, advice) = classify(rule.family, rule.purpose, false);
                let snippet: String = line.trim().chars().take(120).collect();
                out.push(Finding {
                    path: path.to_string(),
                    line: Some(i + 1),
                    source: Source::Code,
                    algorithm: rule.label.to_string(),
                    family: rule.family,
                    purpose: rule.purpose,
                    risk,
                    tier,
                    detail: format!("matched `{}` in: {snippet}", m.as_str().trim()),
                    advice,
                    long_lived: false,
                });
            }
        }
    }
}
