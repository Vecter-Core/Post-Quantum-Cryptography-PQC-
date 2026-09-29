package org.vecter.vpqc.jca;

import java.security.Provider;
import java.security.ProviderException;

/**
 * Java Cryptography Architecture provider for vpqc.
 *
 * <pre>{@code
 * Security.addProvider(new VpqcProvider());
 *
 * KeyPairGenerator kpg = KeyPairGenerator.getInstance("VPQC-SIG", "VPQC");
 * kpg.initialize(new VpqcParameterSpec(Profile.STANDARD));  // Ed25519 + ML-DSA-65
 * KeyPair kp = kpg.generateKeyPair();
 *
 * Signature s = Signature.getInstance("VPQC-SIG", "VPQC");
 * s.setParameter(new VpqcSignatureParameterSpec("my-app/v1"));  // mandatory context
 * s.initSign(kp.getPrivate());
 * s.update(data);
 * byte[] sig = s.sign();
 *
 * KEM kem = KEM.getInstance("VPQC-KEM", "VPQC");                // JDK 21+
 * KEM.Encapsulated e = kem.newEncapsulator(kemKeys.getPublic()).encapsulate();
 * }</pre>
 *
 * <p>Services: {@code KeyPairGenerator} "VPQC-SIG" and "VPQC-KEM", {@code Signature} "VPQC-SIG",
 * {@code KEM} "VPQC-KEM", {@code KeyFactory} "VPQC". Randomness always comes from the operating
 * system CSPRNG inside the native core; {@code SecureRandom} arguments are ignored.
 *
 * <p>Pre-release and unaudited: do not protect real secrets with it yet.
 */
public final class VpqcProvider extends Provider {
    private static final long serialVersionUID = 1L;

    /** Provider name used with {@code getInstance(algorithm, "VPQC")}. */
    public static final String NAME = "VPQC";

    /** Creates the provider. */
    public VpqcProvider() {
        super(NAME, "0.0.1", "vpqc post-quantum and hybrid cryptography (pre-release)");
        putService(new Svc(this, "KeyPairGenerator", "VPQC-SIG", () -> new VpqcKeyPairGeneratorSpi(false)));
        putService(new Svc(this, "KeyPairGenerator", "VPQC-KEM", () -> new VpqcKeyPairGeneratorSpi(true)));
        putService(new Svc(this, "Signature", "VPQC-SIG", VpqcSignatureSpi::new));
        putService(new Svc(this, "KEM", "VPQC-KEM", VpqcKemSpi::new));
        putService(new Svc(this, "KeyFactory", "VPQC", VpqcKeyFactorySpi::new));
    }

    /** A service that constructs its SPI directly instead of through reflection. */
    private static final class Svc extends Service {
        private final java.util.function.Supplier<Object> factory;

        Svc(Provider p, String type, String alg, java.util.function.Supplier<Object> factory) {
            super(p, type, alg, VpqcProvider.class.getName() + "$" + type + "$" + alg, null, null);
            this.factory = factory;
        }

        @Override
        public Object newInstance(Object constructorParameter) {
            try {
                return factory.get();
            } catch (RuntimeException e) {
                throw new ProviderException("cannot create " + getType() + "/" + getAlgorithm(), e);
            }
        }
    }
}
