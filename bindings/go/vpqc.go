// Package vpqc provides post-quantum cryptography with safe defaults, backed by the Rust
// core through its C ABI (cgo).
//
// Pre-release and unaudited: do not protect real secrets with it yet.
//
// Build the native library first:
//
//	cargo build -p vpqc-ffi --release
//
// The default #cgo flags link the static archive ../../target/release/libvpqc_ffi.a, so the
// resulting Go binary has no runtime dependency on the Rust library:
//
//	go test ./...
//
// For other layouts override with CGO_LDFLAGS="/path/to/libvpqc_ffi.a -lpthread -ldl -lm" and
// CGO_CFLAGS="-I/path/to/include" (Linux; macOS/Windows flags differ).
package vpqc

/*
#cgo CFLAGS: -I${SRCDIR}/../../crates/vpqc-ffi/include
#cgo LDFLAGS: ${SRCDIR}/../../target/release/libvpqc_ffi.a -lpthread -ldl -lm
#include <stdlib.h>
#include "vpqc.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

// Profile selects a vetted combination of algorithms.
type Profile int

const (
	// ProfileStandard: hybrid X25519+ML-KEM-768 (X-Wing) and composite Ed25519+ML-DSA-65.
	ProfileStandard Profile = C.VPQC_PROFILE_STANDARD
	// ProfileFastAuth: hybrid KEM, classical Ed25519 signatures. Short-lived authentication only.
	ProfileFastAuth Profile = C.VPQC_PROFILE_FAST_AUTH
	// ProfileCNSA2: ML-KEM-1024 and ML-DSA-87 without a classical component.
	ProfileCNSA2 Profile = C.VPQC_PROFILE_CNSA2
	// ProfileHigh: hybrid P-384 + ML-KEM-1024 and composite ECDSA-P384 + ML-DSA-87 for long-lived data.
	ProfileHigh Profile = C.VPQC_PROFILE_HIGH
)

// Sentinel errors; use errors.Is.
var (
	// ErrDecryption: wrong key, wrong context, or tampered data.
	ErrDecryption = errors.New("vpqc: decryption failed")
	// ErrVerification: the signature is not valid for this key, message and context.
	ErrVerification = errors.New("vpqc: signature verification failed")
	// ErrInvalidInput: a key, envelope or argument is malformed or of the wrong kind.
	ErrInvalidInput = errors.New("vpqc: invalid input")
	// ErrIO: an operating-system I/O error (file not found, permission denied, ...).
	ErrIO = errors.New("vpqc: I/O error")
)

// Error is a failure reported by the native library.
type Error struct {
	Code    int
	Message string
}

func (e *Error) Error() string { return "vpqc: " + e.Message }

// Is maps native codes onto the sentinel errors.
func (e *Error) Is(target error) bool {
	switch target {
	case ErrDecryption:
		return e.Code == C.VPQC_ERR_DECRYPTION_FAILED
	case ErrVerification:
		return e.Code == C.VPQC_ERR_VERIFICATION_FAILED
	case ErrIO:
		return e.Code == C.VPQC_ERR_IO
	case ErrInvalidInput:
		switch e.Code {
		case C.VPQC_ERR_INVALID_ARGUMENT, C.VPQC_ERR_INVALID_KEY, C.VPQC_ERR_ALGORITHM_MISMATCH,
			C.VPQC_ERR_UNSUPPORTED, C.VPQC_ERR_FORMAT, C.VPQC_ERR_CONTEXT_TOO_LONG:
			return true
		}
	}
	return false
}

func check(rc C.int) error {
	if rc == C.VPQC_OK {
		return nil
	}
	return &Error{Code: int(rc), Message: C.GoString(C.vpqc_error_message(rc))}
}

// PublicKey is an encoded public key. Safe to share.
type PublicKey struct{ b []byte }

// SecretKey is an encoded secret key. Keep it private; it is unencrypted.
type SecretKey struct{ b []byte }

// PublicKeyFromBytes wraps an encoded public key (validated on use).
func PublicKeyFromBytes(b []byte) PublicKey { return PublicKey{append([]byte(nil), b...)} }

// SecretKeyFromBytes wraps an encoded secret key (validated on use).
func SecretKeyFromBytes(b []byte) SecretKey { return SecretKey{append([]byte(nil), b...)} }

// Bytes returns the binary encoding.
func (k PublicKey) Bytes() []byte { return append([]byte(nil), k.b...) }

// Bytes returns the binary encoding. Unencrypted.
func (k SecretKey) Bytes() []byte { return append([]byte(nil), k.b...) }

// String never prints key material.
func (k SecretKey) String() string { return "vpqc.SecretKey(<redacted>)" }

// GoString never prints key material.
func (k SecretKey) GoString() string { return k.String() }

// Format prevents accidental disclosure through fmt verbs such as %v or %x.
func (k SecretKey) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(k.String())) }

func keyToText(kind C.int, b []byte) (string, error) {
	var out C.vpqc_buf
	if err := check(C.vpqc_key_to_text(kind, ptr(b), C.size_t(len(b)), &out)); err != nil {
		return "", err
	}
	return string(take(&out)), nil
}

func keyFromText(kind C.int, text string) ([]byte, error) {
	b := []byte(text)
	var out C.vpqc_buf
	if err := check(C.vpqc_key_from_text(kind, ptr(b), C.size_t(len(b)), &out)); err != nil {
		return nil, err
	}
	return take(&out), nil
}

// Text returns the armored text encoding ("-----BEGIN VPQC PUBLIC KEY-----").
func (k PublicKey) Text() (string, error) { return keyToText(C.VPQC_KEY_PUBLIC, k.b) }

// Text returns the armored text encoding. It is unencrypted; protect it.
func (k SecretKey) Text() (string, error) { return keyToText(C.VPQC_KEY_SECRET, k.b) }

// PublicKeyFromText parses an armored public key.
func PublicKeyFromText(text string) (PublicKey, error) {
	b, err := keyFromText(C.VPQC_KEY_PUBLIC, text)
	return PublicKey{b}, err
}

// SecretKeyFromText parses an armored secret key.
func SecretKeyFromText(text string) (SecretKey, error) {
	b, err := keyFromText(C.VPQC_KEY_SECRET, text)
	return SecretKey{b}, err
}

// ptr returns a pointer to the first byte, or nil for an empty slice (allowed by the ABI).
func ptr(b []byte) *C.uint8_t {
	if len(b) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0]))
}

// take copies a native buffer into Go memory and frees (zeroizes) the native one.
func take(buf *C.vpqc_buf) []byte {
	out := []byte{}
	if buf.ptr != nil && buf.len > 0 {
		out = C.GoBytes(unsafe.Pointer(buf.ptr), C.int(buf.len))
	}
	C.vpqc_buf_free(buf)
	return out
}

func keygen(profile Profile, encrypt bool) (PublicKey, SecretKey, error) {
	var pub, sec C.vpqc_buf
	var rc C.int
	if encrypt {
		rc = C.vpqc_encryption_keygen(C.int(profile), &pub, &sec)
	} else {
		rc = C.vpqc_signing_keygen(C.int(profile), &pub, &sec)
	}
	if err := check(rc); err != nil {
		return PublicKey{}, SecretKey{}, err
	}
	return PublicKey{take(&pub)}, SecretKey{take(&sec)}, nil
}

// GenerateEncryptionKeypair creates a key pair for Seal / Open.
func GenerateEncryptionKeypair(profile Profile) (PublicKey, SecretKey, error) {
	return keygen(profile, true)
}

// GenerateSigningKeypair creates a key pair for Sign / Verify.
func GenerateSigningKeypair(profile Profile) (PublicKey, SecretKey, error) {
	return keygen(profile, false)
}

// Seal encrypts plaintext to pk. aad is authenticated context that Open must receive again.
func Seal(pk PublicKey, plaintext, aad []byte) ([]byte, error) {
	var out C.vpqc_buf
	rc := C.vpqc_seal(ptr(pk.b), C.size_t(len(pk.b)), ptr(plaintext), C.size_t(len(plaintext)),
		ptr(aad), C.size_t(len(aad)), &out)
	if err := check(rc); err != nil {
		return nil, err
	}
	return take(&out), nil
}

// Open decrypts a message produced by Seal. It returns an error matching ErrDecryption for a
// wrong key, wrong aad or any modification.
func Open(sk SecretKey, sealed, aad []byte) ([]byte, error) {
	var out C.vpqc_buf
	rc := C.vpqc_open(ptr(sk.b), C.size_t(len(sk.b)), ptr(sealed), C.size_t(len(sealed)),
		ptr(aad), C.size_t(len(aad)), &out)
	if err := check(rc); err != nil {
		return nil, err
	}
	return take(&out), nil
}

// Sign signs message under context (at most 255 bytes; mandatory domain separation such as
// "my-app/release-v1").
func Sign(sk SecretKey, message, context []byte) ([]byte, error) {
	var out C.vpqc_buf
	rc := C.vpqc_sign(ptr(sk.b), C.size_t(len(sk.b)), ptr(message), C.size_t(len(message)),
		ptr(context), C.size_t(len(context)), &out)
	if err := check(rc); err != nil {
		return nil, err
	}
	return take(&out), nil
}

// Verify checks a detached signature. It returns nil only if the signature is valid, otherwise
// an error matching ErrVerification (or ErrInvalidInput for malformed keys).
func Verify(pk PublicKey, message, context, signature []byte) error {
	return check(C.vpqc_verify(ptr(pk.b), C.size_t(len(pk.b)), ptr(message), C.size_t(len(message)),
		ptr(context), C.size_t(len(context)), ptr(signature), C.size_t(len(signature))))
}

// EncryptFile stream-encrypts the file at inPath into outPath (any size, constant memory;
// the output is replaced atomically). It returns the number of plaintext bytes.
func EncryptFile(pk PublicKey, inPath, outPath string, aad []byte) (uint64, error) {
	in, out := C.CString(inPath), C.CString(outPath)
	defer C.free(unsafe.Pointer(in))
	defer C.free(unsafe.Pointer(out))
	var n C.uint64_t
	err := check(C.vpqc_encrypt_file(ptr(pk.b), C.size_t(len(pk.b)), ptr(aad), C.size_t(len(aad)), in, out, &n))
	return uint64(n), err
}

// cKeyArrays copies public keys into C memory (cgo forbids passing Go memory that holds Go
// pointers). Call the returned function to free them.
func cKeyArrays(recipients []PublicKey) (**C.uint8_t, *C.size_t, func(), error) {
	if len(recipients) == 0 || len(recipients) > 32 {
		return nil, nil, nil, fmt.Errorf("%w: between 1 and 32 recipients required", ErrInvalidInput)
	}
	count := len(recipients)
	keys := (*[32]*C.uint8_t)(C.malloc(C.size_t(count) * C.size_t(unsafe.Sizeof(uintptr(0)))))
	lens := (*[32]C.size_t)(C.malloc(C.size_t(count) * C.size_t(unsafe.Sizeof(C.size_t(0)))))
	for i, pk := range recipients {
		keys[i] = (*C.uint8_t)(C.CBytes(pk.b))
		lens[i] = C.size_t(len(pk.b))
	}
	free := func() {
		for i := 0; i < count; i++ {
			C.free(unsafe.Pointer(keys[i]))
		}
		C.free(unsafe.Pointer(keys))
		C.free(unsafe.Pointer(lens))
	}
	return &keys[0], &lens[0], free, nil
}

// EncryptFileMulti is EncryptFile for several recipients (1 to 32, e.g. a user key and a
// recovery key): each can decrypt with DecryptFile and their own secret key. With a single
// recipient it still writes the multi-recipient (envelope) format, so the recipients can later
// be changed with RewrapFile (key rotation).
func EncryptFileMulti(recipients []PublicKey, inPath, outPath string, aad []byte) (uint64, error) {
	keys, lens, free, err := cKeyArrays(recipients)
	if err != nil {
		return 0, err
	}
	defer free()
	in, out := C.CString(inPath), C.CString(outPath)
	defer C.free(unsafe.Pointer(in))
	defer C.free(unsafe.Pointer(out))
	var n C.uint64_t
	err = check(C.vpqc_encrypt_file_multi(keys, lens, C.size_t(len(recipients)), ptr(aad), C.size_t(len(aad)), in, out, &n))
	return uint64(n), err
}

// RewrapFile changes the recipients of a multi-recipient file without re-encrypting its data.
// sk must belong to a current recipient; the output is readable by exactly the new recipients.
// Removing a recipient does not revoke what they already decrypted. It returns the number of
// body bytes copied.
func RewrapFile(sk SecretKey, recipients []PublicKey, inPath, outPath string, aad []byte) (uint64, error) {
	keys, lens, free, err := cKeyArrays(recipients)
	if err != nil {
		return 0, err
	}
	defer free()
	in, out := C.CString(inPath), C.CString(outPath)
	defer C.free(unsafe.Pointer(in))
	defer C.free(unsafe.Pointer(out))
	var n C.uint64_t
	err = check(C.vpqc_rewrap_file(ptr(sk.b), C.size_t(len(sk.b)), keys, lens, C.size_t(len(recipients)),
		ptr(aad), C.size_t(len(aad)), in, out, &n))
	return uint64(n), err
}

// DecryptFile decrypts a file produced by EncryptFile. The output file appears (mode 0600 on
// Unix) only if the whole stream verifies; errors.Is(err, ErrDecryption) otherwise.
func DecryptFile(sk SecretKey, inPath, outPath string, aad []byte) (uint64, error) {
	in, out := C.CString(inPath), C.CString(outPath)
	defer C.free(unsafe.Pointer(in))
	defer C.free(unsafe.Pointer(out))
	var n C.uint64_t
	err := check(C.vpqc_decrypt_file(ptr(sk.b), C.size_t(len(sk.b)), ptr(aad), C.size_t(len(aad)), in, out, &n))
	return uint64(n), err
}

// ABIVersion returns the native ABI version (major<<16 | minor).
func ABIVersion() uint32 { return uint32(C.vpqc_abi_version()) }
