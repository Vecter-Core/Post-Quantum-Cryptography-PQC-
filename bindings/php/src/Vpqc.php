<?php

declare(strict_types=1);

namespace Vecter\Vpqc;

/**
 * Post-quantum cryptography with safe defaults.
 *
 * Pre-release and unaudited: do not protect real secrets with it yet.
 *
 *     $keys = Vpqc::generateEncryptionKeypair();
 *     $sealed = Vpqc::seal($keys->public, 'secret', 'ctx');
 *     Vpqc::open($keys->secret, $sealed, 'ctx');   // 'secret'
 *
 * Strings are byte strings (binary safe).
 */
final class Vpqc
{
    private function __construct()
    {
    }

    /** Key pair for {@see seal()} / {@see open()}. */
    public static function generateEncryptionKeypair(Profile $profile = Profile::Standard): KeyPair
    {
        return Native::keygen($profile->value, true);
    }

    /** Key pair for {@see sign()} / {@see verify()}. */
    public static function generateSigningKeypair(Profile $profile = Profile::Standard): KeyPair
    {
        return Native::keygen($profile->value, false);
    }

    /** Encrypt to a recipient. $aad is authenticated context that open() must receive again. */
    public static function seal(PublicKey $recipient, string $plaintext, string $aad = ''): string
    {
        return Native::call3('vpqc_seal', $recipient->toBytes(), $plaintext, $aad);
    }

    /**
     * Decrypt a sealed message.
     *
     * @throws DecryptionException for a wrong key, wrong $aad or any modification
     */
    public static function open(SecretKey $secret, string $sealed, string $aad = ''): string
    {
        return Native::call3('vpqc_open', $secret->raw(), $sealed, $aad);
    }

    /** Sign under a mandatory domain-separation context of at most 255 bytes. */
    public static function sign(SecretKey $secret, string $message, string $context): string
    {
        return Native::call3('vpqc_sign', $secret->raw(), $message, $context);
    }

    /** @throws VerificationException if the signature is not valid */
    public static function verify(PublicKey $public, string $message, string $context, string $signature): void
    {
        Native::verify($public->toBytes(), $message, $context, $signature);
    }

    /** Native ABI version (major << 16 | minor). */
    public static function abiVersion(): int
    {
        return Native::abiVersion();
    }
}
