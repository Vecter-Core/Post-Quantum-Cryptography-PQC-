package org.vecter.vpqc.jca;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Objects;
import javax.crypto.DecapsulateException;
import javax.crypto.KEM;
import javax.crypto.KEMSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.vecter.vpqc.Vpqc;
import org.vecter.vpqc.VpqcException;

/**
 * {@code KEM} "VPQC-KEM" (JDK 21+): X-Wing, MLKEM1024-P384, ML-KEM-1024 depending on the key.
 * The shared secret is 32 bytes.
 */
final class VpqcKemSpi implements KEMSpi {
    private static final int SECRET_SIZE = 32;

    @Override
    public EncapsulatorSpi engineNewEncapsulator(PublicKey publicKey, AlgorithmParameterSpec spec, SecureRandom random)
            throws InvalidAlgorithmParameterException, InvalidKeyException {
        if (spec != null) {
            throw new InvalidAlgorithmParameterException("VPQC-KEM takes no parameters");
        }
        VpqcKeys.VpqcPublicKey key = VpqcKeys.publicKey(publicKey);
        if (!VpqcKeys.isKem(key.algorithmId())) {
            throw new InvalidKeyException("not a KEM public key");
        }
        int ctLen = VpqcKeys.ciphertextLength(key.algorithmId());
        return new EncapsulatorSpi() {
            @Override
            public int engineSecretSize() {
                return SECRET_SIZE;
            }

            @Override
            public int engineEncapsulationSize() {
                return ctLen;
            }

            @Override
            public KEM.Encapsulated engineEncapsulate(int from, int to, String algorithm) {
                Objects.checkFromToIndex(from, to, SECRET_SIZE);
                Objects.requireNonNull(algorithm, "algorithm");
                byte[][] r = Vpqc.kemEncapsulate(key.toVpqc());
                try {
                    return new KEM.Encapsulated(new SecretKeySpec(r[0], from, to - from, algorithm), r[1], null);
                } finally {
                    Arrays.fill(r[0], (byte) 0);
                }
            }
        };
    }

    @Override
    public DecapsulatorSpi engineNewDecapsulator(PrivateKey privateKey, AlgorithmParameterSpec spec)
            throws InvalidAlgorithmParameterException, InvalidKeyException {
        if (spec != null) {
            throw new InvalidAlgorithmParameterException("VPQC-KEM takes no parameters");
        }
        VpqcKeys.VpqcPrivateKey key = VpqcKeys.privateKey(privateKey);
        if (!VpqcKeys.isKem(key.algorithmId())) {
            throw new InvalidKeyException("not a KEM private key");
        }
        int ctLen = VpqcKeys.ciphertextLength(key.algorithmId());
        return new DecapsulatorSpi() {
            @Override
            public int engineSecretSize() {
                return SECRET_SIZE;
            }

            @Override
            public int engineEncapsulationSize() {
                return ctLen;
            }

            @Override
            public SecretKey engineDecapsulate(byte[] encapsulation, int from, int to, String algorithm)
                    throws DecapsulateException {
                Objects.checkFromToIndex(from, to, SECRET_SIZE);
                Objects.requireNonNull(algorithm, "algorithm");
                if (encapsulation.length != ctLen) {
                    throw new DecapsulateException("encapsulation must be " + ctLen + " bytes");
                }
                byte[] ss;
                try {
                    ss = Vpqc.kemDecapsulate(key.toVpqc(), encapsulation);
                } catch (VpqcException e) {
                    throw new DecapsulateException(e.getMessage(), e);
                }
                try {
                    return new SecretKeySpec(ss, from, to - from, algorithm);
                } finally {
                    Arrays.fill(ss, (byte) 0);
                }
            }
        };
    }
}
