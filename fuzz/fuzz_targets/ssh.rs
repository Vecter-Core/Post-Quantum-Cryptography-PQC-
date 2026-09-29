//! SSH: an untrusted KEXINIT payload or KexAlgorithms value never panics; every accepted name
//! is a valid SSH algorithm name, and an accepted KEXINIT re-encodes to the same lists.
#![no_main]
use libfuzzer_sys::fuzz_target;
use vpqc_ssh::{audit_kex_directive, classify_kex, parse_kexinit};

fn name_list(out: &mut Vec<u8>, names: &[String]) {
    let joined = names.join(",");
    out.extend_from_slice(&(joined.len() as u32).to_be_bytes());
    out.extend_from_slice(joined.as_bytes());
}

fuzz_target!(|data: &[u8]| {
    if let Ok(k) = parse_kexinit(data) {
        let lists = [
            &k.kex,
            &k.host_keys,
            &k.ciphers_client_to_server,
            &k.ciphers_server_to_client,
            &k.macs_client_to_server,
            &k.macs_server_to_client,
        ];
        for name in lists.iter().flat_map(|l| l.iter()) {
            assert!(!name.is_empty() && name.len() <= 64);
            assert!(name.bytes().all(|b| (0x21..=0x7e).contains(&b) && b != b','));
            let _ = classify_kex(name);
        }
        let mut again = vec![20];
        again.extend_from_slice(&[0; 16]);
        for l in lists {
            name_list(&mut again, l);
        }
        for _ in 0..4 {
            name_list(&mut again, &[]);
        }
        again.extend_from_slice(&[0; 5]);
        assert_eq!(parse_kexinit(&again).unwrap(), k);
    }
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = audit_kex_directive(text);
    }
});
