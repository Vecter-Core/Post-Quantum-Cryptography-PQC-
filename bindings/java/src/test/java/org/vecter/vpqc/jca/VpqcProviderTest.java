package org.vecter.vpqc.jca;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.DecapsulateException;
import javax.crypto.KEM;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.vecter.vpqc.Profile;

/** Uses vpqc only through the standard JCA API. */
class VpqcProviderTest {
    private static final byte[] MSG = "release-1.0.tar.gz".getBytes(StandardCharsets.UTF_8);

    @BeforeAll
    static void register() {
        Security.addProvider(new VpqcProvider());
    }

    private static KeyPair keys(String alg, Profile p) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(alg, "VPQC");
        kpg.initialize(new VpqcParameterSpec(p));
        return kpg.generateKeyPair();
    }

    private static byte[] sign(PrivateKey k, String ctx, byte[] msg) throws Exception {
        Signature s = Signature.getInstance("VPQC-SIG", "VPQC");
        s.setParameter(new VpqcSignatureParameterSpec(ctx));
        s.initSign(k);
        s.update(msg, 0, 5);
        s.update(msg, 5, msg.length - 5); // streaming updates
        return s.sign();
    }

    private static boolean verify(PublicKey k, String ctx, byte[] msg, byte[] sig) throws Exception {
        Signature s = Signature.getInstance("VPQC-SIG", "VPQC");
        s.setParameter(new VpqcSignatureParameterSpec(ctx));
        s.initVerify(k);
        s.update(msg);
        return s.verify(sig);
    }

    @Test
    void signatureAllProfiles() throws Exception {
        for (Profile p : Profile.values()) {
            KeyPair kp = keys("VPQC-SIG", p);
            byte[] sig = sign(kp.getPrivate(), "app/v1", MSG);
            assertTrue(verify(kp.getPublic(), "app/v1", MSG, sig), p.name());
            assertFalse(verify(kp.getPublic(), "app/v2", MSG, sig), "wrong context");
            assertFalse(verify(kp.getPublic(), "app/v1", "other".getBytes(StandardCharsets.UTF_8), sig));
            assertFalse(verify(keys("VPQC-SIG", p).getPublic(), "app/v1", MSG, sig), "wrong key");
        }
    }

    @Test
    void contextIsMandatory() throws Exception {
        KeyPair kp = keys("VPQC-SIG", Profile.STANDARD);
        Signature s = Signature.getInstance("VPQC-SIG", "VPQC");
        s.initSign(kp.getPrivate());
        s.update(MSG);
        SignatureException e = assertThrows(SignatureException.class, s::sign);
        assertTrue(e.getMessage().contains("context"));
        assertThrows(IllegalArgumentException.class, () -> new VpqcSignatureParameterSpec(new byte[256]));
    }

    @Test
    void kemAllProfiles() throws Exception {
        KEM kem = KEM.getInstance("VPQC-KEM", "VPQC");
        for (Profile p : Profile.values()) {
            KeyPair kp = keys("VPQC-KEM", p);
            KEM.Encapsulator enc = kem.newEncapsulator(kp.getPublic());
            KEM.Encapsulated e = enc.encapsulate();
            assertEquals(32, enc.secretSize());
            assertEquals(enc.encapsulationSize(), e.encapsulation().length);
            SecretKey k2 = kem.newDecapsulator(kp.getPrivate()).decapsulate(e.encapsulation());
            assertArrayEquals(e.key().getEncoded(), k2.getEncoded(), p.name());
            assertEquals("Generic", e.key().getAlgorithm());

            // Sub-range as an AES key.
            KEM.Encapsulated aes = enc.encapsulate(0, 16, "AES");
            SecretKey aes2 = kem.newDecapsulator(kp.getPrivate()).decapsulate(aes.encapsulation(), 0, 16, "AES");
            assertArrayEquals(aes.key().getEncoded(), aes2.getEncoded());
            assertEquals(16, aes2.getEncoded().length);
        }
    }

    @Test
    void kemRejectsWrongInputs() throws Exception {
        KEM kem = KEM.getInstance("VPQC-KEM", "VPQC");
        KeyPair kp = keys("VPQC-KEM", Profile.STANDARD);
        KEM.Encapsulated e = kem.newEncapsulator(kp.getPublic()).encapsulate();
        byte[] bad = e.encapsulation().clone();
        bad[3] ^= 1;
        // Implicit rejection: a different key, not an exception.
        assertNotEquals(new String(e.key().getEncoded(), StandardCharsets.ISO_8859_1),
                new String(kem.newDecapsulator(kp.getPrivate()).decapsulate(bad).getEncoded(), StandardCharsets.ISO_8859_1));
        assertThrows(DecapsulateException.class, () -> kem.newDecapsulator(kp.getPrivate()).decapsulate(new byte[10]));
        KeyPair sig = keys("VPQC-SIG", Profile.STANDARD);
        assertThrows(InvalidKeyException.class, () -> kem.newEncapsulator(sig.getPublic()));
        assertThrows(InvalidKeyException.class, () -> Signature.getInstance("VPQC-SIG", "VPQC").initSign(kp.getPrivate()));
    }

    @Test
    void keyFactoryRoundTripAndValidation() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("VPQC", "VPQC");
        KeyPair kp = keys("VPQC-SIG", Profile.HIGH);
        PublicKey pub = kf.generatePublic(new VpqcEncodedKeySpec(kp.getPublic().getEncoded()));
        PrivateKey priv = kf.generatePrivate(new VpqcEncodedKeySpec(kp.getPrivate().getEncoded()));
        assertEquals(kp.getPublic(), pub);
        assertTrue(verify(pub, "c", MSG, sign(priv, "c", MSG)));
        byte[] corrupt = kp.getPublic().getEncoded();
        corrupt[20] ^= 1;
        assertThrows(InvalidKeySpecException.class, () -> kf.generatePublic(new VpqcEncodedKeySpec(corrupt)));
        assertEquals("VPQC", pub.getFormat());
        assertEquals("VPQC-SIG", pub.getAlgorithm());
    }

    @Test
    void privateKeyHygiene() throws Exception {
        KeyPair kp = keys("VPQC-SIG", Profile.STANDARD);
        assertEquals("VpqcPrivateKey(<redacted>)", kp.getPrivate().toString());
        ((javax.security.auth.Destroyable) kp.getPrivate()).destroy();
        assertTrue(((javax.security.auth.Destroyable) kp.getPrivate()).isDestroyed());
        assertThrows(IllegalStateException.class, () -> sign(kp.getPrivate(), "c", MSG));
        assertThrows(java.io.NotSerializableException.class, () ->
                new java.io.ObjectOutputStream(new java.io.ByteArrayOutputStream()).writeObject(keys("VPQC-KEM", Profile.STANDARD).getPrivate()));
    }

    @Test
    void keySizeInitIsRejected() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("VPQC-SIG", "VPQC");
        assertThrows(InvalidParameterException.class, () -> kpg.initialize(2048));
        // Default profile without initialize(): STANDARD.
        assertEquals("VPQC-SIG", kpg.generateKeyPair().getPublic().getAlgorithm());
    }
}
