<?php

declare(strict_types=1);

namespace Vecter\Vpqc;

/** A vetted combination of algorithms. Pick a profile, not an algorithm. */
enum Profile: int
{
    /** Hybrid X25519 + ML-KEM-768 (X-Wing) and composite Ed25519 + ML-DSA-65. */
    case Standard = 1;
    /** Hybrid KEM, classical Ed25519 signatures. Short-lived authentication only. */
    case FastAuth = 2;
    /** ML-KEM-1024 and ML-DSA-87 without a classical component. */
    case Cnsa2 = 3;
    /** Hybrid P-384 + ML-KEM-1024 and composite ECDSA-P384 + ML-DSA-87, for long-lived data. */
    case High = 4;
}
