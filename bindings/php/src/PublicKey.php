<?php

declare(strict_types=1);

namespace Vecter\Vpqc;

/** An encoded public key. Safe to share. */
final class PublicKey
{
    private function __construct(private readonly string $bytes)
    {
    }

    /** Wrap a binary-encoded public key (validated on use). */
    public static function fromBytes(string $bytes): self
    {
        return new self($bytes);
    }

    /** Parse an armored text public key. */
    public static function fromText(string $text): self
    {
        return new self(Native::keyFromText(Native::KEY_PUBLIC, $text));
    }

    public function toBytes(): string
    {
        return $this->bytes;
    }

    /** Armored text ("-----BEGIN VPQC PUBLIC KEY-----"). */
    public function toText(): string
    {
        return Native::keyToText(Native::KEY_PUBLIC, $this->bytes);
    }

    public function __toString(): string
    {
        return 'PublicKey(' . strlen($this->bytes) . ' bytes)';
    }
}
