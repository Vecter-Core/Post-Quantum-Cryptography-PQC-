<?php

declare(strict_types=1);

namespace Vecter\Vpqc;

/** A freshly generated key pair. */
final class KeyPair
{
    public function __construct(
        public readonly PublicKey $public,
        public readonly SecretKey $secret,
    ) {
    }
}
