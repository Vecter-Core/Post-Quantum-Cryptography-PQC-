package org.vecter.vpqc;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import javax.security.auth.Destroyable;

/**
 * An encoded secret key. Never printed. Call {@link #destroy()} to wipe the in-memory copy
 * (the JVM may still hold other copies made by the garbage collector).
 */
public final class SecretKey implements Destroyable {
    private final byte[] bytes;
    private boolean destroyed;

    private SecretKey(byte[] bytes) {
        this.bytes = bytes;
    }

    /**
     * Wraps a binary-encoded secret key (validated on use).
     *
     * @param bytes encoded key
     * @return the key
     */
    public static SecretKey fromBytes(byte[] bytes) {
        return new SecretKey(bytes.clone());
    }

    /**
     * Parses an armored text secret key.
     *
     * @param text armored text
     * @return the key
     */
    public static SecretKey fromText(String text) {
        return new SecretKey(Native.keyFromText(Native.KEY_SECRET, text));
    }

    /**
     * Decrypts a passphrase-protected key (ADR-0013: Argon2id, XChaCha20-Poly1305), as written
     * by {@link #toProtectedText}, any other vpqc binding, or {@code vpqc keygen --passphrase}.
     *
     * @param text armored {@code VPQC PROTECTED SECRET KEY} text
     * @param passphrase the passphrase; the temporary UTF-8 copies are wiped
     * @return the key
     * @throws VpqcException.DecryptionException for a wrong passphrase or a modified key
     */
    public static SecretKey fromProtected(String text, char[] passphrase) {
        return fromProtected(text.getBytes(StandardCharsets.UTF_8), passphrase);
    }

    /**
     * Decrypts a passphrase-protected key given as armored text bytes or in binary form.
     *
     * @param data protected key
     * @param passphrase the passphrase; the temporary UTF-8 copies are wiped
     * @return the key
     */
    public static SecretKey fromProtected(byte[] data, char[] passphrase) {
        byte[] p = utf8(passphrase);
        try {
            return new SecretKey(Native.unprotectSecretKey(data, p));
        } finally {
            Arrays.fill(p, (byte) 0);
        }
    }

    /**
     * @param data armored text bytes or binary
     * @return whether {@code data} is a protected secret key
     */
    public static boolean isProtected(byte[] data) {
        return Native.isProtectedSecretKey(data);
    }

    /**
     * Armored text encrypted under a passphrase with the default Argon2id cost (64 MiB).
     *
     * @param passphrase the passphrase (not empty); the temporary UTF-8 copies are wiped
     * @return {@code VPQC PROTECTED SECRET KEY} text
     */
    public String toProtectedText(char[] passphrase) {
        return toProtectedText(passphrase, 0);
    }

    /**
     * Armored text encrypted under a passphrase.
     *
     * @param passphrase the passphrase (not empty); the temporary UTF-8 copies are wiped
     * @param memoryKib Argon2id memory in KiB: 0 for the default (64 MiB), else 8192 to 1048576
     * @return {@code VPQC PROTECTED SECRET KEY} text
     */
    public String toProtectedText(char[] passphrase, int memoryKib) {
        byte[] p = utf8(passphrase);
        try {
            return Native.protectSecretKey(raw(), p, memoryKib);
        } finally {
            Arrays.fill(p, (byte) 0);
        }
    }

    private static byte[] utf8(char[] chars) {
        java.nio.ByteBuffer b = StandardCharsets.UTF_8.encode(java.nio.CharBuffer.wrap(chars));
        byte[] out = new byte[b.remaining()];
        b.get(out);
        if (b.hasArray()) {
            Arrays.fill(b.array(), (byte) 0);
        }
        return out;
    }

    /** @return the binary encoding (unencrypted) */
    public byte[] toBytes() {
        return raw().clone();
    }

    /** @return armored text (unencrypted) */
    public String toText() {
        return Native.keyToText(Native.KEY_SECRET, raw());
    }

    /** @return the internal encoding without copying (package use only). */
    byte[] raw() {
        if (destroyed) {
            throw new IllegalStateException("secret key has been destroyed");
        }
        return bytes;
    }

    @Override
    public void destroy() {
        Arrays.fill(bytes, (byte) 0);
        destroyed = true;
    }

    @Override
    public boolean isDestroyed() {
        return destroyed;
    }

    @Override
    public String toString() {
        return "SecretKey(<redacted>)";
    }
}
