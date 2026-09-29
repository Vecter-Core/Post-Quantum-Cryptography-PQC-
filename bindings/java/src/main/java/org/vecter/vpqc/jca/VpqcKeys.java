package org.vecter.vpqc.jca;

import java.security.InvalidKeyException;
import java.security.Key;
import java.util.Arrays;
import javax.security.auth.Destroyable;
import org.vecter.vpqc.PublicKey;
import org.vecter.vpqc.SecretKey;

/** JCA key types wrapping vpqc keys. */
public final class VpqcKeys {
    /** Encoding format name reported by {@link Key#getFormat()}. */
    public static final String FORMAT = "VPQC";

    private VpqcKeys() {}

    /** Algorithm id stored in bytes 6..7 of a vpqc key encoding (see vpqc-format). */
    static int algorithmId(byte[] encoded) {
        if (encoded.length < 12 || encoded[0] != 'V' || encoded[1] != 'P' || encoded[2] != 'Q' || encoded[3] != 'C') {
            return -1;
        }
        return ((encoded[6] & 0xff) << 8) | (encoded[7] & 0xff);
    }

    static boolean isKem(int algorithmId) {
        return algorithmId >= 0x0001 && algorithmId <= 0x00ff;
    }

    static boolean isSignature(int algorithmId) {
        return algorithmId >= 0x0101 && algorithmId <= 0x01ff;
    }

    /** KEM ciphertext length for a KEM algorithm id. */
    static int ciphertextLength(int algorithmId) {
        return switch (algorithmId) {
            case 0x0001 -> 1120; // X-Wing
            case 0x0002 -> 1088; // ML-KEM-768
            case 0x0003 -> 1568; // ML-KEM-1024
            case 0x0004 -> 1665; // MLKEM1024-P384
            default -> throw new IllegalArgumentException("not a KEM key");
        };
    }

    /** A vpqc public key usable with JCA. */
    public static final class VpqcPublicKey implements java.security.PublicKey {
        private static final long serialVersionUID = 1L;
        private final byte[] encoded;

        VpqcPublicKey(byte[] encoded) {
            this.encoded = encoded.clone();
        }

        /**
         * Wraps a vpqc {@link PublicKey}.
         *
         * @param key the key
         * @return the JCA key
         */
        public static VpqcPublicKey of(PublicKey key) {
            return new VpqcPublicKey(key.toBytes());
        }

        /** @return the vpqc key */
        public PublicKey toVpqc() {
            return PublicKey.fromBytes(encoded);
        }

        int algorithmId() {
            return VpqcKeys.algorithmId(encoded);
        }

        @Override
        public String getAlgorithm() {
            return isKem(algorithmId()) ? "VPQC-KEM" : "VPQC-SIG";
        }

        @Override
        public String getFormat() {
            return FORMAT;
        }

        @Override
        public byte[] getEncoded() {
            return encoded.clone();
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof VpqcPublicKey k && Arrays.equals(encoded, k.encoded);
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(encoded);
        }
    }

    /** A vpqc private key usable with JCA. Never printed; {@link #destroy()} wipes it. */
    public static final class VpqcPrivateKey implements java.security.PrivateKey, Destroyable {
        private static final long serialVersionUID = 1L;
        private final transient SecretKey key;
        private final int algorithmId;

        VpqcPrivateKey(byte[] encoded) {
            this.key = SecretKey.fromBytes(encoded);
            this.algorithmId = VpqcKeys.algorithmId(encoded);
        }

        /**
         * Wraps a vpqc {@link SecretKey}.
         *
         * @param key the key
         * @return the JCA key
         */
        public static VpqcPrivateKey of(SecretKey key) {
            return new VpqcPrivateKey(key.toBytes());
        }

        /** @return the vpqc key */
        public SecretKey toVpqc() {
            return key;
        }

        int algorithmId() {
            return algorithmId;
        }

        @Override
        public String getAlgorithm() {
            return isKem(algorithmId) ? "VPQC-KEM" : "VPQC-SIG";
        }

        @Override
        public String getFormat() {
            return FORMAT;
        }

        @Override
        public byte[] getEncoded() {
            return key.toBytes();
        }

        @Override
        public void destroy() {
            key.destroy();
        }

        @Override
        public boolean isDestroyed() {
            return key.isDestroyed();
        }

        @Override
        public String toString() {
            return "VpqcPrivateKey(<redacted>)";
        }

        private void writeObject(java.io.ObjectOutputStream out) throws java.io.IOException {
            throw new java.io.NotSerializableException("VpqcPrivateKey");
        }
    }

    static VpqcPublicKey publicKey(Key key) throws InvalidKeyException {
        if (key instanceof VpqcPublicKey k) {
            return k;
        }
        if (key instanceof java.security.PublicKey && FORMAT.equals(key.getFormat()) && key.getEncoded() != null) {
            return new VpqcPublicKey(key.getEncoded());
        }
        throw new InvalidKeyException("not a vpqc public key: " + (key == null ? "null" : key.getClass().getName()));
    }

    static VpqcPrivateKey privateKey(Key key) throws InvalidKeyException {
        if (key instanceof VpqcPrivateKey k) {
            return k;
        }
        throw new InvalidKeyException("not a vpqc private key: " + (key == null ? "null" : key.getClass().getName()));
    }
}
