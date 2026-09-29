//! Every parser: never panics, and whatever parses re-encodes to exactly the same bytes
//! (one encoding per object, no ignored trailing data).
#![no_main]
use libfuzzer_sys::fuzz_target;
use vpqc_format::{
    DetachedSignature, Sealed, StreamHeader, armor, dearmor, decode_public_key, decode_secret_key,
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
    if let Ok(h) = StreamHeader::decode_prefix(data) {
        let enc = h.encode().unwrap();
        assert_eq!(&data[..enc.len()], &enc[..]);
    }
    if let Ok(text) = std::str::from_utf8(data) {
        for label in ["VPQC PUBLIC KEY", "VPQC SECRET KEY"] {
            if let Ok(bytes) = dearmor(label, text) {
                // Canonical armor of the decoded bytes decodes to the same bytes.
                assert_eq!(dearmor(label, &armor(label, &bytes)).unwrap(), bytes);
            }
        }
    }
    let _ = vpqc::keys::public_from_bytes(data);
    let _ = vpqc::keys::secret_from_bytes(data);
});
