package org.vecter.vpqc;

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
