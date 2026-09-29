<?php

declare(strict_types=1);

namespace Vecter\Vpqc;

use FFI;

/**
 * Bindings to the C ABI (vpqc.h) through PHP's FFI extension.
 *
 * The library is located through the VPQC_LIBRARY environment variable (full path to
 * libvpqc_ffi.so / .dylib / vpqc_ffi.dll) or the default loader path.
 *
 * @internal
 */
final class Native
{
    public const KEY_PUBLIC = 1;
    public const KEY_SECRET = 2;

    private const CDEF = <<<'C'
typedef struct vpqc_buf { unsigned char *ptr; size_t len; } vpqc_buf;
unsigned int vpqc_abi_version(void);
const char *vpqc_error_message(int code);
void vpqc_buf_free(vpqc_buf *buf);
int vpqc_encryption_keygen(int profile, vpqc_buf *public_out, vpqc_buf *secret_out);
int vpqc_signing_keygen(int profile, vpqc_buf *public_out, vpqc_buf *secret_out);
int vpqc_seal(const char *pk, size_t pk_len, const char *pt, size_t pt_len, const char *aad, size_t aad_len, vpqc_buf *out);
int vpqc_open(const char *sk, size_t sk_len, const char *sealed, size_t sealed_len, const char *aad, size_t aad_len, vpqc_buf *out);
int vpqc_sign(const char *sk, size_t sk_len, const char *msg, size_t msg_len, const char *ctx, size_t ctx_len, vpqc_buf *out);
int vpqc_verify(const char *pk, size_t pk_len, const char *msg, size_t msg_len, const char *ctx, size_t ctx_len, const char *sig, size_t sig_len);
int vpqc_key_to_text(int kind, const char *key, size_t key_len, vpqc_buf *out);
int vpqc_key_from_text(int kind, const char *text, size_t text_len, vpqc_buf *out);
int vpqc_secret_key_protect(const char *sk, size_t sk_len, const char *pass, size_t pass_len, uint32_t memory_kib, vpqc_buf *out);
int vpqc_secret_key_unprotect(const char *data, size_t data_len, const char *pass, size_t pass_len, vpqc_buf *out);
int vpqc_secret_key_is_protected(const char *data, size_t data_len);
int vpqc_encrypt_file(const char *pk, size_t pk_len, const char *aad, size_t aad_len, const char *in, const char *out, uint64_t *n);
int vpqc_decrypt_file(const char *sk, size_t sk_len, const char *aad, size_t aad_len, const char *in, const char *out, uint64_t *n);
int vpqc_encrypt_file_multi(const unsigned char **pks, const size_t *pk_lens, size_t count, const char *aad, size_t aad_len, const char *in, const char *out, uint64_t *n);
int vpqc_rewrap_file(const char *sk, size_t sk_len, const unsigned char **pks, const size_t *pk_lens, size_t count, const char *aad, size_t aad_len, const char *in, const char *out, uint64_t *n);
C;

    private static ?FFI $ffi = null;

    private static function ffi(): FFI
    {
        if (self::$ffi === null) {
            $lib = getenv('VPQC_LIBRARY');
            if ($lib === false || $lib === '') {
                $lib = PHP_OS_FAMILY === 'Darwin' ? 'libvpqc_ffi.dylib'
                    : (PHP_OS_FAMILY === 'Windows' ? 'vpqc_ffi.dll' : 'libvpqc_ffi.so');
            }
            self::$ffi = FFI::cdef(self::CDEF, $lib);
        }
        return self::$ffi;
    }

    private static function check(int $rc): void
    {
        if ($rc !== 0) {
            // PHP FFI converts a returned `const char *` to a PHP string automatically.
            $msg = (string) self::ffi()->vpqc_error_message($rc);
            throw VpqcException::fromCode($rc, $msg);
        }
    }

    /** Copy a native buffer into a PHP string, then free (zeroize) it. */
    private static function take(\FFI\CData $buf): string
    {
        $out = $buf->len > 0 ? FFI::string($buf->ptr, $buf->len) : '';
        self::ffi()->vpqc_buf_free(FFI::addr($buf));
        return $out;
    }

    public static function abiVersion(): int
    {
        return self::ffi()->vpqc_abi_version();
    }

    public static function keygen(int $profile, bool $encrypt): KeyPair
    {
        $ffi = self::ffi();
        $pub = $ffi->new('vpqc_buf');
        $sec = $ffi->new('vpqc_buf');
        $rc = $encrypt
            ? $ffi->vpqc_encryption_keygen($profile, FFI::addr($pub), FFI::addr($sec))
            : $ffi->vpqc_signing_keygen($profile, FFI::addr($pub), FFI::addr($sec));
        self::check($rc);
        return new KeyPair(PublicKey::fromBytes(self::take($pub)), SecretKey::fromBytes(self::take($sec)));
    }

    /** seal / open / sign share the shape (a, b, c) -> buffer. */
    public static function call3(string $fn, string $a, string $b, string $c): string
    {
        $ffi = self::ffi();
        $out = $ffi->new('vpqc_buf');
        self::check($ffi->$fn($a, strlen($a), $b, strlen($b), $c, strlen($c), FFI::addr($out)));
        return self::take($out);
    }

    public static function verify(string $pk, string $msg, string $ctx, string $sig): void
    {
        self::check(self::ffi()->vpqc_verify($pk, strlen($pk), $msg, strlen($msg), $ctx, strlen($ctx), $sig, strlen($sig)));
    }

    /** vpqc_encrypt_file / vpqc_decrypt_file; returns plaintext bytes. */
    public static function file(string $fn, string $key, string $aad, string $in, string $out): int
    {
        $ffi = self::ffi();
        $n = $ffi->new('uint64_t');
        self::check($ffi->$fn($key, strlen($key), $aad, strlen($aad), $in, $out, FFI::addr($n)));
        return $n->cdata;
    }

    /**
     * vpqc_encrypt_file_multi ($secret === null) or vpqc_rewrap_file.
     *
     * @param list<string> $keys raw public keys
     */
    public static function fileMulti(?string $secret, array $keys, string $aad, string $in, string $out): int
    {
        $ffi = self::ffi();
        $count = count($keys);
        $size = max($count, 1);
        $ptrs = $ffi->new("const unsigned char *[$size]");
        $lens = $ffi->new("size_t[$size]");
        $held = [];
        foreach (array_values($keys) as $i => $key) {
            $buf = $ffi->new('unsigned char[' . max(strlen($key), 1) . ']');
            FFI::memcpy($buf, $key, strlen($key));
            $held[] = $buf; // keep alive until the call returns
            $ptrs[$i] = $ffi->cast('const unsigned char *', $buf);
            $lens[$i] = strlen($key);
        }
        $n = $ffi->new('uint64_t');
        if ($secret === null) {
            $rc = $ffi->vpqc_encrypt_file_multi($ptrs, $lens, $count, $aad, strlen($aad), $in, $out, FFI::addr($n));
        } else {
            $rc = $ffi->vpqc_rewrap_file($secret, strlen($secret), $ptrs, $lens, $count, $aad, strlen($aad), $in, $out, FFI::addr($n));
        }
        self::check($rc);
        return $n->cdata;
    }

    public static function keyToText(int $kind, string $key): string
    {
        $ffi = self::ffi();
        $out = $ffi->new('vpqc_buf');
        self::check($ffi->vpqc_key_to_text($kind, $key, strlen($key), FFI::addr($out)));
        return self::take($out);
    }

    /** Protected secret key text (ABI 1.1, ADR-0013). */
    public static function protectSecretKey(string $key, string $passphrase, int $memoryKib): string
    {
        $ffi = self::ffi();
        $out = $ffi->new('vpqc_buf');
        self::check($ffi->vpqc_secret_key_protect($key, strlen($key), $passphrase, strlen($passphrase), $memoryKib, FFI::addr($out)));
        return self::take($out);
    }

    /** Binary secret key from a passphrase-protected one (ABI 1.1). */
    public static function unprotectSecretKey(string $data, string $passphrase): string
    {
        $ffi = self::ffi();
        $out = $ffi->new('vpqc_buf');
        self::check($ffi->vpqc_secret_key_unprotect($data, strlen($data), $passphrase, strlen($passphrase), FFI::addr($out)));
        return self::take($out);
    }

    public static function isProtectedSecretKey(string $data): bool
    {
        return self::ffi()->vpqc_secret_key_is_protected($data, strlen($data)) === 1;
    }

    public static function keyFromText(int $kind, string $text): string
    {
        $ffi = self::ffi();
        $out = $ffi->new('vpqc_buf');
        self::check($ffi->vpqc_key_from_text($kind, $text, strlen($text), FFI::addr($out)));
        return self::take($out);
    }
}
