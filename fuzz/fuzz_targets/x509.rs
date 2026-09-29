//! X.509: untrusted certificates, PKCS#8 and SPKI never panic; parsed keys re-encode to keys
//! that parse to the same public key; a certificate only verifies if it chains to the anchor.
#![no_main]
use libfuzzer_sys::fuzz_target;
use vpqc_fuzz::x509_pki;
use vpqc_x509::{Certificate, PrivateKey, PublicKey, VerifyOptions, verify_chain};

fuzz_target!(|data: &[u8]| {
    let (root, leaf) = x509_pki();
    if let Ok(k) = PrivateKey::from_pkcs8_der(data) {
        assert_eq!(PrivateKey::from_pkcs8_der(&k.to_pkcs8_der()).unwrap().public_key(), k.public_key());
    }
    if let Ok(k) = PublicKey::from_spki_der(data) {
        assert_eq!(PublicKey::from_spki_der(&k.to_spki_der()).unwrap(), k);
    }
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = Certificate::all_from_pem(text);
        let _ = PrivateKey::from_pkcs8_pem(text);
    }
    if let Ok(cert) = Certificate::from_der(data) {
        let _ = cert.public_key();
        let _ = cert.subject();
        // As a leaf under the fixed root, and as an intermediate for the fixed leaf.
        if verify_chain(&cert, &[], std::slice::from_ref(root), &VerifyOptions::default()).is_ok() {
            // Signatures cannot be forged: an accepted leaf must carry the real leaf's key.
            assert_eq!(cert.public_key().unwrap(), leaf.public_key().unwrap(), "forged certificate accepted");
        }
        let r = verify_chain(leaf, std::slice::from_ref(&cert), std::slice::from_ref(root), &VerifyOptions::default());
        // The fixed leaf is issued directly by the root: any path found must end at the root.
        if let Ok(path) = r {
            assert_eq!(path.last(), Some(root));
        }
    }
});
