//! Every parser: never panics, and whatever parses re-encodes to exactly the same bytes
//! (one encoding per object, no ignored trailing data).
#![no_main]
use libfuzzer_sys::fuzz_target;
use vpqc_format::{
    AnyStreamHeader, DetachedSignature, HeaderScan, Sealed, StreamHeader, armor, dearmor, decode_public_key, decode_secret_key,
    encode_public_key, encode_secret_key,
};

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = Sealed::decode(data) {
        assert_eq!(s.encode(), data);
    }
    if let Ok(s) = DetachedSignature::decode(data) {
        assert_eq!(s.encode(), data);
    }
    if let Ok(k) = decode_public_key(data) {
        assert_eq!(encode_public_key(&k), data);
    }
    if let Ok(k) = decode_secret_key(data) {
        assert_eq!(encode_secret_key(&k), data);
    }
    if let Ok(k) = vpqc_format::protected::ProtectedSecretKey::decode(data) {
        assert_eq!(k.encode().unwrap(), data);
        assert!(vpqc_format::protected::is_protected_secret_key(data));
        // Only the KEK path: the passphrase path would spend up to 1 GiB of Argon2 per input.
        // No seed was encrypted under this KEK, so opening one would be an AEAD forgery.
        assert!(vpqc::protect::unprotect_with_kek(data, &[0x42; 32]).is_err(), "forged protected key opened");
    }
    if let Ok(h) = StreamHeader::decode_prefix(data) {
        let enc = h.encode().unwrap();
        assert_eq!(&data[..enc.len()], &enc[..]);
    }
    // Both stream header kinds: the scanner's length, the parser and the encoder agree.
    if let Ok(HeaderScan::Complete(n)) = AnyStreamHeader::scan(data) {
        if let Ok(h) = AnyStreamHeader::parse(&data[..n]) {
            let enc = match &h {
                AnyStreamHeader::Single(s) => s.encode().unwrap(),
                AnyStreamHeader::Multi(m) => m.encode().unwrap(),
            };
            assert_eq!(&enc[..], &data[..n]);
            assert_eq!(AnyStreamHeader::decode_prefix(data).unwrap(), h);
        }
    }
    if let Ok(text) = std::str::from_utf8(data) {
        for label in ["VPQC PUBLIC KEY", "VPQC SECRET KEY", "VPQC PROTECTED SECRET KEY"] {
            if let Ok(bytes) = dearmor(label, text) {
                // Canonical armor of the decoded bytes decodes to the same bytes.
                assert_eq!(dearmor(label, &armor(label, &bytes)).unwrap(), bytes);
            }
        }
    }
    let _ = vpqc::keys::public_from_bytes(data);
    let _ = vpqc::keys::secret_from_bytes(data);
});
