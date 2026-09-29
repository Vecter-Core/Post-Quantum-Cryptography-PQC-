package org.vecter.vpqc;

/**
 * Post-quantum cryptography with safe defaults.
 *
 * <p><b>Pre-release and unaudited: do not protect real secrets with it yet.</b>
 *
 * <pre>{@code
 * KeyPair keys = Vpqc.generateEncryptionKeypair(Profile.STANDARD);
 * byte[] sealed = Vpqc.seal(keys.publicKey(), data, aad);
 * byte[] plain = Vpqc.open(keys.secretKey(), sealed, aad);
 * }</pre>
 *
 * <p>The native library is located through the system property {@code vpqc.library.path}
 * (a directory), the environment variable {@code VPQC_LIBRARY_PATH}, or the default library
 * search path ({@code System.loadLibrary("vpqc_ffi")}).
 */
public final class Vpqc {
    private Vpqc() {}

    /**
     * Generates a key pair for {@link #seal} / {@link #open}.
     *
     * @param profile the profile
     * @return the key pair
     */
    public static KeyPair generateEncryptionKeypair(Profile profile) {
        return Native.keygen(profile.id, true);
    }

    /**
     * Generates a key pair for {@link #sign} / {@link #verify}.
     *
     * @param profile the profile
     * @return the key pair
     */
    public static KeyPair generateSigningKeypair(Profile profile) {
        return Native.keygen(profile.id, false);
    }

    /**
     * Encrypts {@code plaintext} to a recipient. {@code aad} is authenticated context that
     * {@link #open} must receive again.
     *
     * @param recipient recipient public key
     * @param plaintext data to encrypt
     * @param aad authenticated context (may be empty)
     * @return the sealed message
     */
    public static byte[] seal(PublicKey recipient, byte[] plaintext, byte[] aad) {
        return Native.call3("vpqc_seal", recipient.raw(), plaintext, aad);
    }

    /**
     * Decrypts a sealed message.
     *
     * @param secret recipient secret key
     * @param sealed sealed message
     * @param aad the context used when sealing
     * @return the plaintext
     * @throws VpqcException.DecryptionException for a wrong key, wrong {@code aad} or any
     *     modification
     */
    public static byte[] open(SecretKey secret, byte[] sealed, byte[] aad) {
        return Native.call3("vpqc_open", secret.raw(), sealed, aad);
    }

    /**
     * Signs a message under a mandatory domain-separation context.
     *
     * @param secret signing key
     * @param message message to sign
     * @param context context of at most 255 bytes, for example {@code "my-app/release-v1"}
     * @return the detached signature
     */
    public static byte[] sign(SecretKey secret, byte[] message, byte[] context) {
        return Native.call3("vpqc_sign", secret.raw(), message, context);
    }

    /**
     * Verifies a detached signature.
     *
     * @param publicKey verification key
     * @param message the message
     * @param context the context used when signing
     * @param signature the signature
     * @throws VpqcException.VerificationException if the signature is not valid
     */
    public static void verify(PublicKey publicKey, byte[] message, byte[] context, byte[] signature) {
        Native.verify(publicKey.raw(), message, context, signature);
    }

    /**
     * Raw KEM encapsulation, for protocols that need a shared secret (and for the JCA
     * {@code KEM} service). Prefer {@link #seal} for application data.
     *
     * @param recipient encryption public key
     * @return {shared secret (32 bytes), KEM ciphertext}
     */
    public static byte[][] kemEncapsulate(PublicKey recipient) {
        return Native.kemEncapsulate(recipient.raw());
    }

    /**
     * Raw KEM decapsulation. ML-KEM uses implicit rejection: a modified ciphertext yields an
     * unrelated secret rather than an error.
     *
     * @param secret encryption secret key
     * @param ciphertext KEM ciphertext
     * @return the 32-byte shared secret
     */
    public static byte[] kemDecapsulate(SecretKey secret, byte[] ciphertext) {
        return Native.kemDecapsulate(secret.raw(), ciphertext);
    }

    /** @return the native ABI version ({@code major << 16 | minor}) */
    public static int abiVersion() {
        return Native.abiVersion();
    }
}
