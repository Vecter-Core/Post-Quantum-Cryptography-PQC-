package org.vecter.vpqc;

import java.util.Arrays;

/** An encoded public key. Safe to share. */
public final class PublicKey {
    private final byte[] bytes;

    private PublicKey(byte[] bytes) {
        this.bytes = bytes;
    }

    /**
     * Wraps a binary-encoded public key (validated on use).
     *
     * @param bytes encoded key
     * @return the key
     */
    public static PublicKey fromBytes(byte[] bytes) {
        return new PublicKey(bytes.clone());
    }

    /**
     * Parses an armored text public key.
     *
     * @param text armored text
     * @return the key
     */
    public static PublicKey fromText(String text) {
        return new PublicKey(Native.keyFromText(Native.KEY_PUBLIC, text));
    }

    /** @return the binary encoding */
    public byte[] toBytes() {
        return bytes.clone();
    }

    /** @return armored text ("-----BEGIN VPQC PUBLIC KEY-----") */
    public String toText() {
        return Native.keyToText(Native.KEY_PUBLIC, bytes);
    }

    byte[] raw() {
        return bytes;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof PublicKey other && Arrays.equals(bytes, other.bytes);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(bytes);
    }

    @Override
    public String toString() {
        return "PublicKey(" + bytes.length + " bytes)";
    }
}
