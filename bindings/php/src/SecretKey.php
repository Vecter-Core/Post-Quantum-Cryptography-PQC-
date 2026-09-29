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
