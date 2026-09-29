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

    /* Streaming file encryption */
    {
        vpqc_buf fpk = {0}, fsk = {0};
        CHECK(vpqc_encryption_keygen(VPQC_PROFILE_STANDARD, &fpk, &fsk) == VPQC_OK);
        const char *in = "vpqc-c-smoke.in", *enc = "vpqc-c-smoke.vpqc", *out = "vpqc-c-smoke.out";
        FILE *f = fopen(in, "wb");
        CHECK(f != NULL);
        for (int i = 0; i < 200000; i++) fputc(i & 0xff, f);
        fclose(f);
        uint64_t n = 0;
        CHECK(vpqc_encrypt_file(fpk.ptr, fpk.len, (const uint8_t *)"c", 1, in, enc, &n) == VPQC_OK && n == 200000);
        CHECK(vpqc_decrypt_file(fsk.ptr, fsk.len, (const uint8_t *)"c", 1, enc, out, &n) == VPQC_OK && n == 200000);
        CHECK(vpqc_decrypt_file(fsk.ptr, fsk.len, (const uint8_t *)"x", 1, enc, "vpqc-c-smoke.bad", NULL) == VPQC_ERR_DECRYPTION_FAILED);
        CHECK(fopen("vpqc-c-smoke.bad", "rb") == NULL);
        CHECK(vpqc_encrypt_file(fpk.ptr, fpk.len, NULL, 0, "vpqc-no-such-file", enc, NULL) == VPQC_ERR_IO);
        /* Two recipients: each decrypts with its own key. */
        vpqc_buf pk2 = {0}, sk2 = {0};
        CHECK(vpqc_encryption_keygen(VPQC_PROFILE_HIGH, &pk2, &sk2) == VPQC_OK);
        const uint8_t *keys[2] = {fpk.ptr, pk2.ptr};
        size_t lens[2] = {fpk.len, pk2.len};
        CHECK(vpqc_encrypt_file_multi(keys, lens, 2, (const uint8_t *)"m", 1, in, enc, &n) == VPQC_OK && n == 200000);
        CHECK(vpqc_decrypt_file(fsk.ptr, fsk.len, (const uint8_t *)"m", 1, enc, out, &n) == VPQC_OK && n == 200000);
        CHECK(vpqc_decrypt_file(sk2.ptr, sk2.len, (const uint8_t *)"m", 1, enc, out, &n) == VPQC_OK && n == 200000);
        CHECK(vpqc_encrypt_file_multi(keys, lens, 0, NULL, 0, in, enc, NULL) == VPQC_ERR_INVALID_ARGUMENT);
        /* Re-wrap for the second recipient only; the first can no longer decrypt. */
        const char *re = "vpqc-c-smoke.re";
        CHECK(vpqc_rewrap_file(fsk.ptr, fsk.len, keys + 1, lens + 1, 1, (const uint8_t *)"m", 1, enc, re, NULL) == VPQC_OK);
        CHECK(vpqc_decrypt_file(sk2.ptr, sk2.len, (const uint8_t *)"m", 1, re, out, &n) == VPQC_OK && n == 200000);
        CHECK(vpqc_decrypt_file(fsk.ptr, fsk.len, (const uint8_t *)"m", 1, re, "vpqc-c-smoke.bad", NULL) == VPQC_ERR_DECRYPTION_FAILED);
        remove(re);
        vpqc_buf_free(&pk2); vpqc_buf_free(&sk2);
        remove(in); remove(enc); remove(out);
        vpqc_buf_free(&fpk); vpqc_buf_free(&fsk);
        puts("stream file: OK");
    }

    {
        /* Passphrase-protected secret key (ABI 1.1). */
        vpqc_buf epk = {0}, esk = {0}, text = {0}, back = {0};
        const char *pass = "correct horse battery staple";
        CHECK((vpqc_abi_version() & 0xffff) >= VPQC_ABI_VERSION_MINOR);
        CHECK(vpqc_encryption_keygen(VPQC_PROFILE_STANDARD, &epk, &esk) == VPQC_OK);
        CHECK(vpqc_secret_key_protect(esk.ptr, esk.len, (const uint8_t *)pass, strlen(pass), 8192, &text) == VPQC_OK);
        CHECK(vpqc_secret_key_is_protected(text.ptr, text.len) == 1);
        CHECK(vpqc_secret_key_is_protected(esk.ptr, esk.len) == 0);
        CHECK(vpqc_secret_key_unprotect(text.ptr, text.len, (const uint8_t *)pass, strlen(pass), &back) == VPQC_OK);
        CHECK(back.len == esk.len && memcmp(back.ptr, esk.ptr, esk.len) == 0);
        vpqc_buf_free(&back);
        CHECK(vpqc_secret_key_unprotect(text.ptr, text.len, (const uint8_t *)"nope", 4, &back) == VPQC_ERR_DECRYPTION_FAILED);
        CHECK(back.ptr == NULL);
        vpqc_buf_free(&epk); vpqc_buf_free(&esk); vpqc_buf_free(&text);
        puts("protected secret key: OK");
    }

    CHECK(strcmp(vpqc_error_message(VPQC_ERR_DECRYPTION_FAILED), "decryption failed") == 0);
    puts("C smoke test OK");
    return 0;
}
