<?php

declare(strict_types=1);

namespace Vecter\Vpqc;

/**
 * An encoded secret key. Never printed or var_dump'ed. PHP cannot guarantee that no other copy
 * of the key remains in memory; call {@see destroy()} to wipe this instance's copy.
 */
final class SecretKey
{
    private ?string $bytes;

    private function __construct(string $bytes)
    {
        $this->bytes = $bytes;
    }

    /** Wrap a binary-encoded secret key (validated on use). */
    public static function fromBytes(string $bytes): self
    {
        return new self($bytes);
    }

    /** Parse an armored text secret key. */
    public static function fromText(string $text): self
    {
        return new self(Native::keyFromText(Native::KEY_SECRET, $text));
    }

    /**
     * Decrypt a passphrase-protected key (ADR-0013: Argon2id, XChaCha20-Poly1305), armored text
     * or binary, as written by {@see toProtectedText()}, another vpqc binding or
     * `vpqc keygen --passphrase`. Throws DecryptionException for a wrong passphrase.
     */
    public static function fromProtected(string $data, string $passphrase): self
    {
        return new self(Native::unprotectSecretKey($data, $passphrase));
    }

    /** Whether $data is a protected secret key (armored or binary). */
    public static function isProtected(string $data): bool
    {
        return Native::isProtectedSecretKey($data);
    }

    /**
     * Armored text encrypted under $passphrase. $memoryKib is the Argon2id memory: 0 for the
     * default (64 MiB), else 8192 to 1048576.
     */
    public function toProtectedText(string $passphrase, int $memoryKib = 0): string
    {
        return Native::protectSecretKey($this->raw(), $passphrase, $memoryKib);
    }

    /** Binary encoding (unencrypted). */
    public function toBytes(): string
    {
        return $this->raw();
    }

    /** Armored text (unencrypted). */
    public function toText(): string
    {
        return Native::keyToText(Native::KEY_SECRET, $this->raw());
    }

    /** @internal */
    public function raw(): string
    {
        return $this->bytes ?? throw new \LogicException('secret key has been destroyed');
    }

    /** Wipe this instance's copy of the key. */
    public function destroy(): void
    {
        if ($this->bytes !== null) {
            if (function_exists('sodium_memzero')) {
                sodium_memzero($this->bytes);
            }
            $this->bytes = null;
        }
    }

    public function __toString(): string
    {
        return 'SecretKey(<redacted>)';
    }

    /** @return array<string, string> */
    public function __debugInfo(): array
    {
        return ['key' => '<redacted>'];
    }

    public function __serialize(): array
    {
        throw new \LogicException('SecretKey cannot be serialized');
    }
}
