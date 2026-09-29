//! Exercises the C ABI through its `extern "C"` functions, including error paths.
#![allow(unsafe_code, clippy::undocumented_unsafe_blocks)]

use std::ffi::CStr;

use vpqc_ffi::*;

fn empty() -> vpqc_buf {
    vpqc_buf {
        ptr: std::ptr::null_mut(),
        len: 0,
    }
}

fn bytes(b: &vpqc_buf) -> Vec<u8> {
    if b.ptr.is_null() {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(b.ptr, b.len) }.to_vec()
    }
}

fn keygen(
    f: unsafe extern "C" fn(i32, *mut vpqc_buf, *mut vpqc_buf) -> i32,
    profile: i32,
) -> (Vec<u8>, Vec<u8>) {
    let (mut p, mut s) = (empty(), empty());
    assert_eq!(unsafe { f(profile, &mut p, &mut s) }, VPQC_OK);
    let out = (bytes(&p), bytes(&s));
    unsafe {
        vpqc_buf_free(&mut p);
        vpqc_buf_free(&mut s);
    }
    out
}

fn seal(pk: &[u8], pt: &[u8], aad: &[u8]) -> (i32, Vec<u8>) {
    let mut out = empty();
    let rc = unsafe {
        vpqc_seal(
            pk.as_ptr(),
            pk.len(),
            pt.as_ptr(),
            pt.len(),
            aad.as_ptr(),
            aad.len(),
            &mut out,
        )
    };
    let v = bytes(&out);
    unsafe { vpqc_buf_free(&mut out) };
    (rc, v)
}

fn open(sk: &[u8], sealed: &[u8], aad: &[u8]) -> (i32, Vec<u8>) {
    let mut out = empty();
    let rc = unsafe {
        vpqc_open(
            sk.as_ptr(),
            sk.len(),
            sealed.as_ptr(),
            sealed.len(),
            aad.as_ptr(),
            aad.len(),
            &mut out,
        )
    };
    let v = bytes(&out);
    unsafe { vpqc_buf_free(&mut out) };
    (rc, v)
}

#[test]
fn abi_version_is_1_0() {
    assert_eq!(vpqc_abi_version(), 1 << 16);
}

#[test]
fn encrypt_round_trip_all_profiles() {
    for profile in 1..=4 {
        let (pk, sk) = keygen(vpqc_encryption_keygen, profile);
        let (rc, sealed) = seal(&pk, b"hello ffi", b"ctx");
        assert_eq!(rc, VPQC_OK);
        assert_eq!(open(&sk, &sealed, b"ctx"), (VPQC_OK, b"hello ffi".to_vec()));
        assert_eq!(open(&sk, &sealed, b"other").0, VPQC_ERR_DECRYPTION_FAILED);
    }
}

#[test]
fn empty_plaintext_with_null_pointers() {
    let (pk, sk) = keygen(vpqc_encryption_keygen, 1);
    let mut out = empty();
    let rc = unsafe {
        vpqc_seal(
            pk.as_ptr(),
            pk.len(),
            std::ptr::null(),
            0,
            std::ptr::null(),
            0,
            &mut out,
        )
    };
    assert_eq!(rc, VPQC_OK);
    let sealed = bytes(&out);
    unsafe { vpqc_buf_free(&mut out) };
    let mut plain = empty();
    let rc = unsafe {
        vpqc_open(
            sk.as_ptr(),
            sk.len(),
            sealed.as_ptr(),
            sealed.len(),
            std::ptr::null(),
            0,
            &mut plain,
        )
    };
    assert_eq!(rc, VPQC_OK);
    assert_eq!(
        (plain.ptr.is_null(), plain.len),
        (true, 0),
        "empty plaintext is an empty buffer"
    );
}

#[test]
fn sign_verify_and_errors() {
    for profile in 1..=4 {
        let (pk, sk) = keygen(vpqc_signing_keygen, profile);
        let mut sig = empty();
        let rc = unsafe {
            vpqc_sign(
                sk.as_ptr(),
                sk.len(),
                b"msg".as_ptr(),
                3,
                b"ctx".as_ptr(),
                3,
                &mut sig,
            )
        };
        assert_eq!(rc, VPQC_OK);
        let s = bytes(&sig);
        unsafe { vpqc_buf_free(&mut sig) };
        let verify = |m: &[u8], c: &[u8]| unsafe {
            vpqc_verify(
                pk.as_ptr(),
                pk.len(),
                m.as_ptr(),
                m.len(),
                c.as_ptr(),
                c.len(),
                s.as_ptr(),
                s.len(),
            )
        };
        assert_eq!(verify(b"msg", b"ctx"), VPQC_OK);
        assert_eq!(verify(b"msg", b"bad"), VPQC_ERR_VERIFICATION_FAILED);
        assert_eq!(verify(b"bad", b"ctx"), VPQC_ERR_VERIFICATION_FAILED);
    }
    let (_, sk) = keygen(vpqc_signing_keygen, 1);
    let long = [0u8; 256];
    let mut out = empty();
    let rc = unsafe {
        vpqc_sign(
            sk.as_ptr(),
            sk.len(),
            b"m".as_ptr(),
            1,
            long.as_ptr(),
            long.len(),
            &mut out,
        )
    };
    assert_eq!(rc, VPQC_ERR_CONTEXT_TOO_LONG);
    assert!(out.ptr.is_null(), "output is cleared on failure");
}

#[test]
fn invalid_arguments_are_reported_not_crashed() {
    let mut p = empty();
    let mut s = empty();
    unsafe {
        assert_eq!(
            vpqc_encryption_keygen(99, &mut p, &mut s),
            VPQC_ERR_UNSUPPORTED
        );
        assert_eq!(
            vpqc_encryption_keygen(0, &mut p, &mut s),
            VPQC_ERR_UNSUPPORTED
        );
        assert_eq!(
            vpqc_encryption_keygen(-5, &mut p, &mut s),
            VPQC_ERR_UNSUPPORTED
        );
        assert_eq!(
            vpqc_encryption_keygen(1, std::ptr::null_mut(), &mut s),
            VPQC_ERR_INVALID_ARGUMENT
        );
        assert_eq!(
            vpqc_encryption_keygen(1, &mut p, std::ptr::null_mut()),
            VPQC_ERR_INVALID_ARGUMENT
        );

        // Null pointer with a non-zero length.
        let mut out = empty();
        assert_eq!(
            vpqc_seal(
                std::ptr::null(),
                5,
                std::ptr::null(),
                0,
                std::ptr::null(),
                0,
                &mut out
            ),
            VPQC_ERR_INVALID_ARGUMENT
        );
        // Null output.
        let (pk, _) = keygen(vpqc_encryption_keygen, 1);
        assert_eq!(
            vpqc_seal(
                pk.as_ptr(),
                pk.len(),
                std::ptr::null(),
                0,
                std::ptr::null(),
                0,
                std::ptr::null_mut()
            ),
            VPQC_ERR_INVALID_ARGUMENT
        );
        // Garbage key.
        let junk = [1u8, 2, 3];
        assert_eq!(
            vpqc_seal(
                junk.as_ptr(),
                3,
                std::ptr::null(),
                0,
                std::ptr::null(),
                0,
                &mut out
            ),
            VPQC_ERR_FORMAT
        );
    }
    // Key of the wrong kind: a signing key cannot encrypt.
    let (spk, ssk) = keygen(vpqc_signing_keygen, 1);
    assert_eq!(seal(&spk, b"x", b"").0, VPQC_ERR_ALGORITHM_MISMATCH);
    // Public key bytes are not a secret key.
    assert_eq!(open(&spk, b"whatever", b"").0, VPQC_ERR_FORMAT);
    let _ = ssk;
}

#[test]
fn free_is_idempotent_and_null_safe() {
    unsafe {
        vpqc_buf_free(std::ptr::null_mut());
        let mut b = empty();
        vpqc_buf_free(&mut b);
    }
    let (pk, _) = keygen(vpqc_encryption_keygen, 1);
    let mut out = empty();
    unsafe {
        assert_eq!(
            vpqc_seal(
                pk.as_ptr(),
                pk.len(),
                b"x".as_ptr(),
                1,
                std::ptr::null(),
                0,
                &mut out
            ),
            VPQC_OK
        );
        assert!(!out.ptr.is_null() && out.len > 0);
        vpqc_buf_free(&mut out);
        assert!(out.ptr.is_null() && out.len == 0);
        vpqc_buf_free(&mut out); // second free is a no-op
    }
}

#[test]
fn error_messages_are_valid_c_strings() {
    for code in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 99, 12345] {
        let s = unsafe { CStr::from_ptr(vpqc_error_message(code)) };
        assert!(!s.to_str().unwrap().is_empty());
    }
}

#[test]
fn key_text_round_trip_and_errors() {
    for kind in [VPQC_KEY_PUBLIC, VPQC_KEY_SECRET] {
        let (pk, sk) = keygen(vpqc_encryption_keygen, 1);
        let key = if kind == VPQC_KEY_PUBLIC { pk } else { sk };
        let mut text = empty();
        assert_eq!(
            unsafe { vpqc_key_to_text(kind, key.as_ptr(), key.len(), &mut text) },
            VPQC_OK
        );
        let t = bytes(&text);
        unsafe { vpqc_buf_free(&mut text) };
        let s = String::from_utf8(t.clone()).unwrap();
        assert!(s.starts_with("-----BEGIN VPQC "), "{s}");
        let mut back = empty();
        assert_eq!(
            unsafe { vpqc_key_from_text(kind, t.as_ptr(), t.len(), &mut back) },
            VPQC_OK
        );
        assert_eq!(bytes(&back), key);
        unsafe { vpqc_buf_free(&mut back) };
        // Wrong kind is rejected.
        let other = if kind == VPQC_KEY_PUBLIC {
            VPQC_KEY_SECRET
        } else {
            VPQC_KEY_PUBLIC
        };
        let mut bad = empty();
        assert_eq!(
            unsafe { vpqc_key_from_text(other, t.as_ptr(), t.len(), &mut bad) },
            VPQC_ERR_FORMAT
        );
    }
    let mut out = empty();
    assert_eq!(
        unsafe { vpqc_key_from_text(7, b"x".as_ptr(), 1, &mut out) },
        VPQC_ERR_INVALID_ARGUMENT
    );
    assert_eq!(
        unsafe { vpqc_key_from_text(1, [0xff, 0xfe].as_ptr(), 2, &mut out) },
        VPQC_ERR_FORMAT
    );
    assert_eq!(
        unsafe { vpqc_key_to_text(1, b"junk".as_ptr(), 4, &mut out) },
        VPQC_ERR_FORMAT
    );
}

#[test]
fn raw_kem_round_trip_and_errors() {
    for profile in 1..=4 {
        let (pk, sk) = keygen(vpqc_encryption_keygen, profile);
        let mut ss1 = [0u8; 32];
        let mut ct = empty();
        assert_eq!(
            unsafe { vpqc_kem_encapsulate(pk.as_ptr(), pk.len(), ss1.as_mut_ptr(), &mut ct) },
            VPQC_OK
        );
        let c = bytes(&ct);
        unsafe { vpqc_buf_free(&mut ct) };
        let mut ss2 = [0u8; 32];
        assert_eq!(
            unsafe {
                vpqc_kem_decapsulate(sk.as_ptr(), sk.len(), c.as_ptr(), c.len(), ss2.as_mut_ptr())
            },
            VPQC_OK
        );
        assert_eq!(ss1, ss2, "profile {profile}");
        assert_ne!(ss1, [0u8; 32]);
    }
    let (spk, ssk) = keygen(vpqc_signing_keygen, 1);
    let mut ss = [0u8; 32];
    let mut ct = empty();
    assert_eq!(
        unsafe { vpqc_kem_encapsulate(spk.as_ptr(), spk.len(), ss.as_mut_ptr(), &mut ct) },
        VPQC_ERR_ALGORITHM_MISMATCH
    );
    assert_eq!(
        unsafe {
            vpqc_kem_decapsulate(
                ssk.as_ptr(),
                ssk.len(),
                [0u8; 4].as_ptr(),
                4,
                ss.as_mut_ptr(),
            )
        },
        VPQC_ERR_ALGORITHM_MISMATCH
    );
    assert_eq!(
        unsafe { vpqc_kem_encapsulate(spk.as_ptr(), spk.len(), std::ptr::null_mut(), &mut ct) },
        VPQC_ERR_INVALID_ARGUMENT
    );
}

#[test]
fn file_stream_round_trip_and_errors() {
    use std::ffi::CString;
    let dir = std::env::temp_dir().join(format!("vpqc-ffi-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let c = |name: &str| CString::new(dir.join(name).to_str().unwrap()).unwrap();
    let data: Vec<u8> = (0..300_000u32).map(|i| i as u8).collect();
    std::fs::write(dir.join("in.bin"), &data).unwrap();
    let (pk, sk) = keygen(vpqc_encryption_keygen, 1);
    let aad = b"ctx";
    let mut n = 0u64;
    let rc = unsafe {
        vpqc_encrypt_file(
            pk.as_ptr(),
            pk.len(),
            aad.as_ptr(),
            3,
            c("in.bin").as_ptr(),
            c("ct.vpqc").as_ptr(),
            &mut n,
        )
    };
    assert_eq!((rc, n), (VPQC_OK, data.len() as u64));
    let rc = unsafe {
        vpqc_decrypt_file(
            sk.as_ptr(),
            sk.len(),
            aad.as_ptr(),
            3,
            c("ct.vpqc").as_ptr(),
            c("out.bin").as_ptr(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, VPQC_OK);
    assert_eq!(std::fs::read(dir.join("out.bin")).unwrap(), data);

    // Wrong aad: decryption failure, no output file.
    let rc = unsafe {
        vpqc_decrypt_file(
            sk.as_ptr(),
            sk.len(),
            b"x".as_ptr(),
            1,
            c("ct.vpqc").as_ptr(),
            c("bad.bin").as_ptr(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, VPQC_ERR_DECRYPTION_FAILED);
    assert!(!dir.join("bad.bin").exists());
    // Missing input: I/O error. Null path: invalid argument.
    let rc = unsafe {
        vpqc_encrypt_file(
            pk.as_ptr(),
            pk.len(),
            std::ptr::null(),
            0,
            c("missing").as_ptr(),
            c("o").as_ptr(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, VPQC_ERR_IO);
    let rc = unsafe {
        vpqc_encrypt_file(
            pk.as_ptr(),
            pk.len(),
            std::ptr::null(),
            0,
            std::ptr::null(),
            c("o").as_ptr(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, VPQC_ERR_INVALID_ARGUMENT);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn multi_recipient_file() {
    use std::ffi::CString;
    let dir = std::env::temp_dir().join(format!("vpqc-ffi-multi-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let c = |name: &str| CString::new(dir.join(name).to_str().unwrap()).unwrap();
    std::fs::write(dir.join("in"), b"for two recipients").unwrap();
    let (pk1, sk1) = keygen(vpqc_encryption_keygen, 1);
    let (pk2, sk2) = keygen(vpqc_encryption_keygen, 4);
    let (_, outsider) = keygen(vpqc_encryption_keygen, 1);
    let ptrs = [pk1.as_ptr(), pk2.as_ptr()];
    let lens = [pk1.len(), pk2.len()];
    let mut n = 0u64;
    let rc = unsafe {
        vpqc_encrypt_file_multi(
            ptrs.as_ptr(),
            lens.as_ptr(),
            2,
            b"a".as_ptr(),
            1,
            c("in").as_ptr(),
            c("ct").as_ptr(),
            &mut n,
        )
    };
    assert_eq!((rc, n), (VPQC_OK, 18));
    for (i, sk) in [&sk1, &sk2].into_iter().enumerate() {
        let out = format!("out{i}");
        let rc = unsafe {
            vpqc_decrypt_file(
                sk.as_ptr(),
                sk.len(),
                b"a".as_ptr(),
                1,
                c("ct").as_ptr(),
                c(&out).as_ptr(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc, VPQC_OK);
        assert_eq!(
            std::fs::read(dir.join(&out)).unwrap(),
            b"for two recipients"
        );
    }
    let rc = unsafe {
        vpqc_decrypt_file(
            outsider.as_ptr(),
            outsider.len(),
            b"a".as_ptr(),
            1,
            c("ct").as_ptr(),
            c("x").as_ptr(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, VPQC_ERR_DECRYPTION_FAILED);
    // Bad arguments: no keys, too many, null arrays, duplicate keys.
    let bad = |ptrs: *const *const u8, lens: *const usize, count: usize| unsafe {
        vpqc_encrypt_file_multi(
            ptrs,
            lens,
            count,
            std::ptr::null(),
            0,
            c("in").as_ptr(),
            c("o").as_ptr(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(
        bad(ptrs.as_ptr(), lens.as_ptr(), 0),
        VPQC_ERR_INVALID_ARGUMENT
    );
    assert_eq!(
        bad(ptrs.as_ptr(), lens.as_ptr(), 33),
        VPQC_ERR_INVALID_ARGUMENT
    );
    assert_eq!(
        bad(std::ptr::null(), lens.as_ptr(), 2),
        VPQC_ERR_INVALID_ARGUMENT
    );
    let dup = [pk1.as_ptr(), pk1.as_ptr()];
    assert_ne!(bad(dup.as_ptr(), lens.as_ptr(), 2), VPQC_OK);
    std::fs::remove_dir_all(&dir).unwrap();
}
