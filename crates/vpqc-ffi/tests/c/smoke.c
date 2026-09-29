/* Smoke test of the public C header. Build and run with tests/c/run.sh. */
#include <stdio.h>
#include <string.h>
#include "vpqc.h"

#define CHECK(cond)                                                    \
    do {                                                               \
        if (!(cond)) {                                                 \
            fprintf(stderr, "FAILED %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            return 1;                                                  \
        }                                                              \
    } while (0)

int main(void) {
    CHECK((vpqc_abi_version() >> 16) == VPQC_ABI_VERSION_MAJOR);

    /* Encrypt / decrypt */
    vpqc_buf pk = {0}, sk = {0}, sealed = {0}, plain = {0};
    CHECK(vpqc_encryption_keygen(VPQC_PROFILE_STANDARD, &pk, &sk) == VPQC_OK);
    const char *msg = "hello from C";
    CHECK(vpqc_seal(pk.ptr, pk.len, (const uint8_t *)msg, strlen(msg), (const uint8_t *)"ctx", 3, &sealed) == VPQC_OK);
    CHECK(vpqc_open(sk.ptr, sk.len, sealed.ptr, sealed.len, (const uint8_t *)"ctx", 3, &plain) == VPQC_OK);
    CHECK(plain.len == strlen(msg) && memcmp(plain.ptr, msg, plain.len) == 0);
    vpqc_buf_free(&plain);
    CHECK(vpqc_open(sk.ptr, sk.len, sealed.ptr, sealed.len, (const uint8_t *)"bad", 3, &plain) == VPQC_ERR_DECRYPTION_FAILED);
    CHECK(plain.ptr == NULL);
    printf("sealed box: %zu bytes (public key %zu, secret key %zu)\n", sealed.len, pk.len, sk.len);
    vpqc_buf_free(&pk); vpqc_buf_free(&sk); vpqc_buf_free(&sealed);

    /* Sign / verify */
    vpqc_buf spk = {0}, ssk = {0}, sig = {0};
    CHECK(vpqc_signing_keygen(VPQC_PROFILE_STANDARD, &spk, &ssk) == VPQC_OK);
    CHECK(vpqc_sign(ssk.ptr, ssk.len, (const uint8_t *)msg, strlen(msg), (const uint8_t *)"app/v1", 6, &sig) == VPQC_OK);
    CHECK(vpqc_verify(spk.ptr, spk.len, (const uint8_t *)msg, strlen(msg), (const uint8_t *)"app/v1", 6, sig.ptr, sig.len) == VPQC_OK);
    CHECK(vpqc_verify(spk.ptr, spk.len, (const uint8_t *)msg, strlen(msg), (const uint8_t *)"app/v2", 6, sig.ptr, sig.len) == VPQC_ERR_VERIFICATION_FAILED);
    printf("signature: %zu bytes\n", sig.len);
    vpqc_buf_free(&spk); vpqc_buf_free(&ssk); vpqc_buf_free(&sig);

    CHECK(strcmp(vpqc_error_message(VPQC_ERR_DECRYPTION_FAILED), "decryption failed") == 0);
    puts("C smoke test OK");
    return 0;
}
