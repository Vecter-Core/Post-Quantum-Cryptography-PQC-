/*
 * vpqc C API. Pre-release (unaudited); ABI version 1.0.
 *
 * Conventions
 *  - Functions return VPQC_OK (0) or a positive error code.
 *  - Output buffers are allocated by the library; release with vpqc_buf_free(),
 *    which zeroizes the memory first (safe for secret keys and plaintexts).
 *  - Inputs are (pointer, length); the pointer may be NULL only when length is 0.
 *  - Keys and signatures use the self-describing binary encodings of vpqc-format.
 *  - Profiles: 1 = standard, 2 = fast-auth, 3 = cnsa2, 4 = high.
 */
#ifndef VPQC_H
#define VPQC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VPQC_ABI_VERSION_MAJOR 1

#define VPQC_OK 0
#define VPQC_ERR_INVALID_ARGUMENT 1
#define VPQC_ERR_RNG 2
#define VPQC_ERR_INVALID_KEY 3
#define VPQC_ERR_ALGORITHM_MISMATCH 4
#define VPQC_ERR_UNSUPPORTED 5
#define VPQC_ERR_FORMAT 6
#define VPQC_ERR_BACKEND 7
#define VPQC_ERR_DECRYPTION_FAILED 8
#define VPQC_ERR_VERIFICATION_FAILED 9
#define VPQC_ERR_CONTEXT_TOO_LONG 10
#define VPQC_ERR_INTERNAL 99

#define VPQC_KEY_PUBLIC 1
#define VPQC_KEY_SECRET 2

#define VPQC_PROFILE_STANDARD 1
#define VPQC_PROFILE_FAST_AUTH 2
#define VPQC_PROFILE_CNSA2 3
#define VPQC_PROFILE_HIGH 4

typedef struct vpqc_buf {
    uint8_t *ptr;
    size_t len;
} vpqc_buf;

/* (major << 16) | minor */
uint32_t vpqc_abi_version(void);

/* Static NUL-terminated description of a status code. */
const char *vpqc_error_message(int code);

/* Zeroize and free a buffer; resets it to empty. NULL is allowed. */
void vpqc_buf_free(vpqc_buf *buf);

int vpqc_encryption_keygen(int profile, vpqc_buf *public_out, vpqc_buf *secret_out);
int vpqc_signing_keygen(int profile, vpqc_buf *public_out, vpqc_buf *secret_out);

int vpqc_seal(const uint8_t *public_key, size_t public_key_len,
              const uint8_t *plaintext, size_t plaintext_len,
              const uint8_t *aad, size_t aad_len,
              vpqc_buf *out);

int vpqc_open(const uint8_t *secret_key, size_t secret_key_len,
              const uint8_t *sealed, size_t sealed_len,
              const uint8_t *aad, size_t aad_len,
              vpqc_buf *out);

int vpqc_sign(const uint8_t *secret_key, size_t secret_key_len,
              const uint8_t *message, size_t message_len,
              const uint8_t *context, size_t context_len,
              vpqc_buf *out);

int vpqc_verify(const uint8_t *public_key, size_t public_key_len,
                const uint8_t *message, size_t message_len,
                const uint8_t *context, size_t context_len,
                const uint8_t *signature, size_t signature_len);

/* Convert between the binary key encoding and armored UTF-8 text ("-----BEGIN VPQC ...").
 * kind: VPQC_KEY_PUBLIC or VPQC_KEY_SECRET. Text output has no trailing NUL.
 * Secret key text is UNENCRYPTED. */
int vpqc_key_to_text(int kind, const uint8_t *key, size_t key_len, vpqc_buf *out);
int vpqc_key_from_text(int kind, const uint8_t *text, size_t text_len, vpqc_buf *out);

/* Raw KEM (for protocols / JCA KEM). Shared secret is always 32 bytes.
 * Prefer vpqc_seal / vpqc_open for application data. */
int vpqc_kem_encapsulate(const uint8_t *public_key, size_t public_key_len,
                         uint8_t shared_secret_out[32], vpqc_buf *ciphertext_out);
int vpqc_kem_decapsulate(const uint8_t *secret_key, size_t secret_key_len,
                         const uint8_t *ciphertext, size_t ciphertext_len,
                         uint8_t shared_secret_out[32]);

#ifdef __cplusplus
}
#endif

#endif /* VPQC_H */
