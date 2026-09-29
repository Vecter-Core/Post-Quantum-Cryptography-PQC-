//! C ABI for vpqc.
//!
//! Conventions:
//! * Every function returns an `int` status: `VPQC_OK` (0) or a negative-free positive
//!   error code (see `vpqc.h`). Nothing unwinds across the boundary; panics become
//!   `VPQC_ERR_INTERNAL`.
//! * Output buffers are `vpqc_buf { ptr, len }` allocated by this library. Release them with
//!   [`vpqc_buf_free`], which also zeroizes the memory (so secret keys and plaintexts are wiped).
//! * Inputs are `(ptr, len)` pairs. `ptr` may be null only when `len` is 0.
//! * Keys and signatures are the binary encodings from `vpqc-format` (self-describing).
//! * The ABI is versioned: [`vpqc_abi_version`] returns `major << 16 | minor`.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;

use vpqc::{Error, Profile, encryption, keys, signing};
use zeroize::Zeroize;

/// ABI version: major in the high 16 bits, minor in the low 16 bits.
const ABI_VERSION: u32 = 1 << 16;

/// Success.
pub const VPQC_OK: i32 = 0;
/// A required pointer was null or an argument was out of range.
pub const VPQC_ERR_INVALID_ARGUMENT: i32 = 1;
/// The random number generator failed.
pub const VPQC_ERR_RNG: i32 = 2;
/// A key or input has an invalid length or value.
pub const VPQC_ERR_INVALID_KEY: i32 = 3;
/// The key belongs to a different algorithm than the operation requires.
pub const VPQC_ERR_ALGORITHM_MISMATCH: i32 = 4;
/// Unknown or unsupported algorithm or profile.
pub const VPQC_ERR_UNSUPPORTED: i32 = 5;
/// Malformed serialized data.
pub const VPQC_ERR_FORMAT: i32 = 6;
/// Failure inside a cryptographic backend.
pub const VPQC_ERR_BACKEND: i32 = 7;
/// Decryption failed: wrong key, wrong context, or tampered data.
pub const VPQC_ERR_DECRYPTION_FAILED: i32 = 8;
/// Signature verification failed.
pub const VPQC_ERR_VERIFICATION_FAILED: i32 = 9;
/// Signing context longer than 255 bytes.
pub const VPQC_ERR_CONTEXT_TOO_LONG: i32 = 10;
/// Key kind selector for the text (armor) conversions.
pub const VPQC_KEY_PUBLIC: i32 = 1;
/// Key kind selector for the text (armor) conversions.
pub const VPQC_KEY_SECRET: i32 = 2;
/// Internal error (a panic was caught at the boundary).
pub const VPQC_ERR_INTERNAL: i32 = 99;

/// An owned byte buffer allocated by the library.
#[repr(C)]
#[derive(Debug)]
pub struct vpqc_buf {
    /// Start of the buffer (null when `len == 0`).
    pub ptr: *mut u8,
    /// Length in bytes.
    pub len: usize,
}

impl vpqc_buf {
    const EMPTY: vpqc_buf = vpqc_buf {
        ptr: ptr::null_mut(),
        len: 0,
    };

    fn from_vec(v: Vec<u8>) -> Self {
        if v.is_empty() {
            return Self::EMPTY;
        }
        let boxed = v.into_boxed_slice();
        let len = boxed.len();
        Self {
            ptr: Box::into_raw(boxed).cast::<u8>(),
            len,
        }
    }
}

fn code(e: &Error) -> i32 {
    match e {
        Error::Rng => VPQC_ERR_RNG,
        Error::InvalidLength { .. } | Error::InvalidKey(_) => VPQC_ERR_INVALID_KEY,
        Error::AlgorithmMismatch => VPQC_ERR_ALGORITHM_MISMATCH,
        Error::Unsupported(_) => VPQC_ERR_UNSUPPORTED,
        Error::Format(_) => VPQC_ERR_FORMAT,
        Error::Backend(_) => VPQC_ERR_BACKEND,
        Error::DecryptionFailed => VPQC_ERR_DECRYPTION_FAILED,
        Error::VerificationFailed => VPQC_ERR_VERIFICATION_FAILED,
        Error::ContextTooLong => VPQC_ERR_CONTEXT_TOO_LONG,
        _ => VPQC_ERR_INTERNAL,
    }
}

/// Borrow `(ptr, len)` as a slice. Null is accepted only for an empty input.
///
/// # Safety
/// If `len > 0`, `ptr` must be valid for reads of `len` bytes for the duration of the call.
unsafe fn slice<'a>(ptr: *const u8, len: usize) -> Result<&'a [u8], i32> {
    if len == 0 {
        Ok(&[])
    } else if ptr.is_null() {
        Err(VPQC_ERR_INVALID_ARGUMENT)
    } else {
        // SAFETY: the caller guarantees `ptr` is valid for `len` bytes; checked non-null above.
        Ok(unsafe { std::slice::from_raw_parts(ptr, len) })
    }
}

/// Write `value` to `out`, or fail if `out` is null.
///
/// # Safety
/// `out` must be null or valid for a write of one `vpqc_buf`.
unsafe fn put(out: *mut vpqc_buf, value: Vec<u8>) -> i32 {
    if out.is_null() {
        return VPQC_ERR_INVALID_ARGUMENT;
    }
    // SAFETY: `out` is non-null and the caller guarantees it is valid for writes.
    unsafe { out.write(vpqc_buf::from_vec(value)) };
    VPQC_OK
}

/// Run `f`, converting panics and library errors into status codes.
fn guard(f: impl FnOnce() -> Result<(), i32>) -> i32 {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => VPQC_OK,
        Ok(Err(c)) => c,
        Err(_) => VPQC_ERR_INTERNAL,
    }
}

/// Zero `out` so callers never see stale data on failure.
///
/// # Safety
/// `out` must be null or valid for a write of one `vpqc_buf`.
unsafe fn clear(out: *mut vpqc_buf) {
    if !out.is_null() {
        // SAFETY: non-null and valid for writes per the caller's contract.
        unsafe { out.write(vpqc_buf::EMPTY) };
    }
}

fn profile(id: i32) -> Result<Profile, i32> {
    u8::try_from(id)
        .ok()
        .and_then(|v| Profile::from_u8(v).ok())
        .ok_or(VPQC_ERR_UNSUPPORTED)
}

/// Returns the ABI version (`major << 16 | minor`).
#[unsafe(no_mangle)]
pub extern "C" fn vpqc_abi_version() -> u32 {
    ABI_VERSION
}

/// Returns a static, NUL-terminated description of a status code.
#[unsafe(no_mangle)]
pub extern "C" fn vpqc_error_message(code: i32) -> *const std::ffi::c_char {
    let msg: &'static [u8] = match code {
        VPQC_OK => b"ok\0",
        VPQC_ERR_INVALID_ARGUMENT => b"invalid argument\0",
        VPQC_ERR_RNG => b"random number generator failure\0",
        VPQC_ERR_INVALID_KEY => b"invalid key or input length\0",
        VPQC_ERR_ALGORITHM_MISMATCH => b"algorithm mismatch\0",
        VPQC_ERR_UNSUPPORTED => b"unsupported algorithm or profile\0",
        VPQC_ERR_FORMAT => b"malformed data\0",
        VPQC_ERR_BACKEND => b"backend error\0",
        VPQC_ERR_DECRYPTION_FAILED => b"decryption failed\0",
        VPQC_ERR_VERIFICATION_FAILED => b"signature verification failed\0",
        VPQC_ERR_CONTEXT_TOO_LONG => b"signing context longer than 255 bytes\0",
        VPQC_ERR_INTERNAL => b"internal error\0",
        _ => b"unknown error\0",
    };
    msg.as_ptr().cast()
}

/// Free a buffer returned by this library. The memory is zeroized first. Safe to call on an
/// empty buffer; the struct is reset to empty afterwards.
///
/// # Safety
/// `buf` must be null, or point to a `vpqc_buf` produced by this library that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vpqc_buf_free(buf: *mut vpqc_buf) {
    if buf.is_null() {
        return;
    }
    // SAFETY: `buf` is non-null and points to a valid `vpqc_buf` per the contract.
    let b = unsafe { buf.read() };
    if !b.ptr.is_null() && b.len > 0 {
        // SAFETY: `ptr`/`len` came from `Box::into_raw` of a boxed slice of exactly `len` bytes.
        let mut boxed = unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(b.ptr, b.len)) };
        boxed.zeroize();
    }
    // SAFETY: `buf` is valid for writes.
    unsafe { buf.write(vpqc_buf::EMPTY) };
}

/// Generate an encryption key pair. `profile`: 1 standard, 2 fast-auth, 3 cnsa2.
/// Keys are returned in their binary encoding.
///
/// # Safety
/// `public_out` and `secret_out` must be valid for writes of one `vpqc_buf` each.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vpqc_encryption_keygen(
    profile_id: i32,
    public_out: *mut vpqc_buf,
    secret_out: *mut vpqc_buf,
) -> i32 {
    // SAFETY: forwarded contract.
    unsafe { keygen(profile_id, true, public_out, secret_out) }
}

/// Generate a signing key pair. `profile`: 1 standard, 2 fast-auth, 3 cnsa2.
///
/// # Safety
/// `public_out` and `secret_out` must be valid for writes of one `vpqc_buf` each.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vpqc_signing_keygen(
    profile_id: i32,
    public_out: *mut vpqc_buf,
    secret_out: *mut vpqc_buf,
) -> i32 {
    // SAFETY: forwarded contract.
    unsafe { keygen(profile_id, false, public_out, secret_out) }
}

/// # Safety
/// `public_out` and `secret_out` must be valid for writes of one `vpqc_buf` each.
unsafe fn keygen(
    profile_id: i32,
    encrypt: bool,
    public_out: *mut vpqc_buf,
    secret_out: *mut vpqc_buf,
) -> i32 {
    // SAFETY: caller guarantees the out pointers are null or valid.
    unsafe {
        clear(public_out);
        clear(secret_out);
    }
    if public_out.is_null() || secret_out.is_null() {
        return VPQC_ERR_INVALID_ARGUMENT;
    }
    guard(|| {
        let p = profile(profile_id)?;
        let pair = if encrypt {
            encryption::generate(p)
        } else {
            signing::generate(p)
        }
        .map_err(|e| code(&e))?;
        let public = keys::public_to_bytes(&pair.public);
        let secret = keys::secret_to_bytes(&pair.secret);
        // SAFETY: out pointers are non-null (checked) and valid per the contract.
        unsafe {
            put(public_out, public);
            put(secret_out, secret);
        }
        Ok(())
    })
}

/// Encrypt `plaintext` to a public key. `aad` is authenticated context (may be empty).
///
/// # Safety
/// Each `(ptr, len)` pair must describe readable memory (null allowed only if `len == 0`);
/// `out` must be valid for a write of one `vpqc_buf`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vpqc_seal(
    public_key: *const u8,
    public_key_len: usize,
    plaintext: *const u8,
    plaintext_len: usize,
    aad: *const u8,
    aad_len: usize,
    out: *mut vpqc_buf,
) -> i32 {
    // SAFETY: `out` is null or valid per the contract.
    unsafe { clear(out) };
    if out.is_null() {
        return VPQC_ERR_INVALID_ARGUMENT;
    }
    guard(|| {
        // SAFETY: pointer/length pairs are valid per the contract.
        let (pk, pt, aad) = unsafe {
            (
                slice(public_key, public_key_len)?,
                slice(plaintext, plaintext_len)?,
                slice(aad, aad_len)?,
            )
        };
        let pk = keys::public_from_bytes(pk).map_err(|e| code(&e))?;
        let sealed = encryption::seal(&pk, pt, aad).map_err(|e| code(&e))?;
        // SAFETY: `out` is non-null and valid.
        unsafe { put(out, sealed) };
        Ok(())
    })
}

/// Decrypt a sealed message. Returns `VPQC_ERR_DECRYPTION_FAILED` for a wrong key, wrong
/// `aad`, or any modification.
///
/// # Safety
/// Each `(ptr, len)` pair must describe readable memory (null allowed only if `len == 0`);
/// `out` must be valid for a write of one `vpqc_buf`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vpqc_open(
    secret_key: *const u8,
    secret_key_len: usize,
    sealed: *const u8,
    sealed_len: usize,
    aad: *const u8,
    aad_len: usize,
    out: *mut vpqc_buf,
) -> i32 {
    // SAFETY: `out` is null or valid per the contract.
    unsafe { clear(out) };
    if out.is_null() {
        return VPQC_ERR_INVALID_ARGUMENT;
    }
    guard(|| {
        // SAFETY: pointer/length pairs are valid per the contract.
        let (sk, sealed, aad) = unsafe {
            (
                slice(secret_key, secret_key_len)?,
                slice(sealed, sealed_len)?,
                slice(aad, aad_len)?,
            )
        };
        let sk = keys::secret_from_bytes(sk).map_err(|e| code(&e))?;
        let plain = encryption::open(&sk, sealed, aad).map_err(|e| code(&e))?;
        // SAFETY: `out` is non-null and valid.
        unsafe { put(out, plain) };
        Ok(())
    })
}

/// Sign `message` under `context` (at most 255 bytes). Returns an encoded detached signature.
///
/// # Safety
/// Each `(ptr, len)` pair must describe readable memory (null allowed only if `len == 0`);
/// `out` must be valid for a write of one `vpqc_buf`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vpqc_sign(
    secret_key: *const u8,
    secret_key_len: usize,
    message: *const u8,
    message_len: usize,
    context: *const u8,
    context_len: usize,
    out: *mut vpqc_buf,
) -> i32 {
    // SAFETY: `out` is null or valid per the contract.
    unsafe { clear(out) };
    if out.is_null() {
        return VPQC_ERR_INVALID_ARGUMENT;
    }
    guard(|| {
        // SAFETY: pointer/length pairs are valid per the contract.
        let (sk, msg, ctx) = unsafe {
            (
                slice(secret_key, secret_key_len)?,
                slice(message, message_len)?,
                slice(context, context_len)?,
            )
        };
        let sk = keys::secret_from_bytes(sk).map_err(|e| code(&e))?;
        let sig = signing::sign(&sk, msg, ctx).map_err(|e| code(&e))?;
        // SAFETY: `out` is non-null and valid.
        unsafe { put(out, sig) };
        Ok(())
    })
}

/// Verify a detached signature. Returns `VPQC_OK` only if it is valid.
///
/// # Safety
/// Each `(ptr, len)` pair must describe readable memory (null allowed only if `len == 0`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vpqc_verify(
    public_key: *const u8,
    public_key_len: usize,
    message: *const u8,
    message_len: usize,
    context: *const u8,
    context_len: usize,
    signature: *const u8,
    signature_len: usize,
) -> i32 {
    guard(|| {
        // SAFETY: pointer/length pairs are valid per the contract.
        let (pk, msg, ctx, sig) = unsafe {
            (
                slice(public_key, public_key_len)?,
                slice(message, message_len)?,
                slice(context, context_len)?,
                slice(signature, signature_len)?,
            )
        };
        let pk = keys::public_from_bytes(pk).map_err(|e| code(&e))?;
        signing::verify(&pk, msg, ctx, sig).map_err(|e| code(&e))
    })
}

/// Convert a binary-encoded key to armored UTF-8 text (no trailing NUL).
/// `kind`: 1 public, 2 secret (secret text is **unencrypted**).
///
/// # Safety
/// `(key, key_len)` must describe readable memory (null allowed only if `key_len == 0`);
/// `out` must be valid for a write of one `vpqc_buf`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vpqc_key_to_text(
    kind: i32,
    key: *const u8,
    key_len: usize,
    out: *mut vpqc_buf,
) -> i32 {
    // SAFETY: `out` is null or valid per the contract.
    unsafe { clear(out) };
    if out.is_null() {
        return VPQC_ERR_INVALID_ARGUMENT;
    }
    guard(|| {
        // SAFETY: pointer/length pair is valid per the contract.
        let key = unsafe { slice(key, key_len)? };
        let text = match kind {
            VPQC_KEY_PUBLIC => {
                keys::public_to_text(&keys::public_from_bytes(key).map_err(|e| code(&e))?)
            }
            VPQC_KEY_SECRET => {
                keys::secret_to_text(&keys::secret_from_bytes(key).map_err(|e| code(&e))?)
            }
            _ => return Err(VPQC_ERR_INVALID_ARGUMENT),
        };
        // SAFETY: `out` is non-null and valid.
        unsafe { put(out, text.into_bytes()) };
        Ok(())
    })
}

/// Parse armored key text into the binary encoding. `kind`: 1 public, 2 secret.
///
/// # Safety
/// `(text, text_len)` must describe readable memory (null allowed only if `text_len == 0`);
/// `out` must be valid for a write of one `vpqc_buf`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vpqc_key_from_text(
    kind: i32,
    text: *const u8,
    text_len: usize,
    out: *mut vpqc_buf,
) -> i32 {
    // SAFETY: `out` is null or valid per the contract.
    unsafe { clear(out) };
    if out.is_null() {
        return VPQC_ERR_INVALID_ARGUMENT;
    }
    guard(|| {
        // SAFETY: pointer/length pair is valid per the contract.
        let text = unsafe { slice(text, text_len)? };
        let text = std::str::from_utf8(text).map_err(|_| VPQC_ERR_FORMAT)?;
        let bytes = match kind {
            VPQC_KEY_PUBLIC => {
                keys::public_to_bytes(&keys::public_from_text(text).map_err(|e| code(&e))?)
            }
            VPQC_KEY_SECRET => {
                keys::secret_to_bytes(&keys::secret_from_text(text).map_err(|e| code(&e))?)
            }
            _ => return Err(VPQC_ERR_INVALID_ARGUMENT),
        };
        // SAFETY: `out` is non-null and valid.
        unsafe { put(out, bytes) };
        Ok(())
    })
}
