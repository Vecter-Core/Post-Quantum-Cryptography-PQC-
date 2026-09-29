package org.vecter.vpqc;

/** A vetted combination of algorithms. Pick a profile, not an algorithm. */
public enum Profile {
    /** Hybrid X25519 + ML-KEM-768 (X-Wing) and composite Ed25519 + ML-DSA-65. */
    STANDARD(1),
    /** Hybrid KEM, classical Ed25519 signatures. For short-lived authentication only. */
    FAST_AUTH(2),
    /** ML-KEM-1024 and ML-DSA-87 without a classical component. */
    CNSA2(3);

    final int id;

    Profile(int id) {
        this.id = id;
    }
}
