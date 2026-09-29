package org.vecter.vpqc.jca;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import org.vecter.vpqc.Profile;
import org.vecter.vpqc.Vpqc;

/** {@code KeyPairGenerator} "VPQC-SIG" / "VPQC-KEM". Default profile: STANDARD. */
final class VpqcKeyPairGeneratorSpi extends KeyPairGeneratorSpi {
    private final boolean kem;
    private Profile profile = Profile.STANDARD;

    VpqcKeyPairGeneratorSpi(boolean kem) {
        this.kem = kem;
    }

    @Override
    public void initialize(int keysize, SecureRandom random) {
        throw new InvalidParameterException("vpqc selects key sizes by profile; use initialize(new VpqcParameterSpec(profile))");
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException {
        if (!(params instanceof VpqcParameterSpec spec)) {
            throw new InvalidAlgorithmParameterException("expected VpqcParameterSpec");
        }
        this.profile = spec.profile();
    }

    @Override
    public KeyPair generateKeyPair() {
        org.vecter.vpqc.KeyPair kp = kem ? Vpqc.generateEncryptionKeypair(profile) : Vpqc.generateSigningKeypair(profile);
        return new KeyPair(VpqcKeys.VpqcPublicKey.of(kp.publicKey()), VpqcKeys.VpqcPrivateKey.of(kp.secretKey()));
    }
}
