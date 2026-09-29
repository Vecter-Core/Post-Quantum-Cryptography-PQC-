package org.vecter.vpqc.jca;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import org.vecter.vpqc.VpqcException;

/**
 * {@code KeyFactory} "VPQC": converts between {@link VpqcEncodedKeySpec} and keys. Keys are
 * validated on conversion (checksum, algorithm, kind).
 */
final class VpqcKeyFactorySpi extends KeyFactorySpi {
    @Override
    protected PublicKey engineGeneratePublic(KeySpec spec) throws InvalidKeySpecException {
        if (!(spec instanceof VpqcEncodedKeySpec s)) {
            throw new InvalidKeySpecException("expected VpqcEncodedKeySpec");
        }
        try {
            org.vecter.vpqc.PublicKey k = org.vecter.vpqc.PublicKey.fromBytes(s.getEncoded());
            k.toText(); // validates the encoding in the native core
            return VpqcKeys.VpqcPublicKey.of(k);
        } catch (VpqcException e) {
            throw new InvalidKeySpecException("not a valid vpqc public key", e);
        }
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec spec) throws InvalidKeySpecException {
        if (!(spec instanceof VpqcEncodedKeySpec s)) {
            throw new InvalidKeySpecException("expected VpqcEncodedKeySpec");
        }
        try {
            org.vecter.vpqc.SecretKey k = org.vecter.vpqc.SecretKey.fromBytes(s.getEncoded());
            k.toText(); // validates the encoding in the native core
            return VpqcKeys.VpqcPrivateKey.of(k);
        } catch (VpqcException e) {
            throw new InvalidKeySpecException("not a valid vpqc private key", e);
        }
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec) throws InvalidKeySpecException {
        if (!keySpec.isAssignableFrom(VpqcEncodedKeySpec.class)) {
            throw new InvalidKeySpecException("only VpqcEncodedKeySpec is supported");
        }
        if (!VpqcKeys.FORMAT.equals(key.getFormat())) {
            throw new InvalidKeySpecException("not a vpqc key");
        }
        return keySpec.cast(new VpqcEncodedKeySpec(key.getEncoded()));
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {
        if (key instanceof VpqcKeys.VpqcPublicKey || key instanceof VpqcKeys.VpqcPrivateKey) {
            return key;
        }
        return VpqcKeys.publicKey(key);
    }
}
