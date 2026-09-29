//! Scanner: certificate, key and source parsing of arbitrary content never panics, and the
//! reports it produces always serialise (text, JSON, CBOM).
#![no_main]
use libfuzzer_sys::fuzz_target;
use vpqc_scan::{Options, scan_bytes, to_cbom, to_json, to_text};

fuzz_target!(|data: &[u8]| {
    let names = ["cert.der", "cert.pem", "id_rsa", "config.py", "key.pub", "etc/ssh/sshd_config"];
    let (sel, content) = data.split_first().map(|(a, b)| (*a, b)).unwrap_or((0, data));
    let options = Options { include_comments: sel & 0x80 != 0, ..Options::default() };
    let report = scan_bytes(names[(sel as usize) % names.len()], content, &options);
    let _ = to_text(&report, true);
    serde_json_check(&to_json(&report));
    serde_json_check(&to_cbom(&report));
});

fn serde_json_check(s: &str) {
    assert!(s.starts_with('{') && s.ends_with('}'));
}
