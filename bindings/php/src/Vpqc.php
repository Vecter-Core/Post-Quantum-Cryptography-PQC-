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

    /** Encrypt a file of any size in constant memory; the output is replaced atomically. */
    public static function encryptFile(PublicKey $recipient, string $input, string $output, string $aad = ''): int
    {
        return Native::file('vpqc_encrypt_file', $recipient->toBytes(), $aad, $input, $output);
    }

    /**
     * Encrypt a file for several recipients (1 to 32); each decrypts with decryptFile() and their
     * own secret key. With one recipient this still writes the envelope format, so recipients can
     * later be changed with rewrapFile() (key rotation).
     *
     * @param list<PublicKey> $recipients
     */
    public static function encryptFileMulti(array $recipients, string $input, string $output, string $aad = ''): int
    {
        return Native::fileMulti(null, array_map(fn (PublicKey $k) => $k->toBytes(), $recipients), $aad, $input, $output);
    }

    /**
     * Change the recipients of a multi-recipient file without re-encrypting it. $secret must
     * belong to a current recipient. Removing a recipient does not revoke what they already read.
     *
     * @param list<PublicKey> $recipients the complete new recipient list
     * @throws DecryptionException if $secret is not a current recipient
     */
    public static function rewrapFile(SecretKey $secret, array $recipients, string $input, string $output, string $aad = ''): int
    {
        return Native::fileMulti($secret->raw(), array_map(fn (PublicKey $k) => $k->toBytes(), $recipients), $aad, $input, $output);
    }

    /**
     * Decrypt a file produced by encryptFile(). The output appears only if the whole stream verifies.
     *
     * @throws DecryptionException for a wrong key, wrong $aad or tampering
     */
    public static function decryptFile(SecretKey $secret, string $input, string $output, string $aad = ''): int
    {
        return Native::file('vpqc_decrypt_file', $secret->raw(), $aad, $input, $output);
    }

    /** Native ABI version (major << 16 | minor). */
    public static function abiVersion(): int
    {
        return Native::abiVersion();
    }
}
