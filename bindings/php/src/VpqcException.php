<?php

declare(strict_types=1);

namespace Vecter\Vpqc;

/** Failure reported by the native library. The status code is in {@see getCode()}. */
class VpqcException extends \RuntimeException
{
    /** @internal */
    public static function fromCode(int $code, string $message): self
    {
        return match ($code) {
            8 => new DecryptionException($message, $code),
            9 => new VerificationException($message, $code),
            1, 3, 4, 5, 6, 10 => new InvalidInputException($message, $code),
            default => new self($message, $code),
        };
    }
}
