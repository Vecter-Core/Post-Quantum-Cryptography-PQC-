package org.vecter.vpqc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class VpqcTest {
    private static byte[] b(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void abiVersion() {
        assertEquals(1, Vpqc.abiVersion() >> 16);
    }

    @Test
    void encryptRoundTripAllProfiles() {
        for (Profile p : Profile.values()) {
            KeyPair keys = Vpqc.generateEncryptionKeypair(p);
            byte[] sealed = Vpqc.seal(keys.publicKey(), b("secret"), b("ctx"));
            assertArrayEquals(b("secret"), Vpqc.open(keys.secretKey(), sealed, b("ctx")), p.name());
        }
    }

    @Test
    void decryptionFailures() {
        KeyPair a = Vpqc.generateEncryptionKeypair(Profile.STANDARD);
        KeyPair other = Vpqc.generateEncryptionKeypair(Profile.STANDARD);
        byte[] sealed = Vpqc.seal(a.publicKey(), b("secret"), b("one"));
        assertThrows(VpqcException.DecryptionException.class,
                () -> Vpqc.open(a.secretKey(), sealed, b("two")));
        assertThrows(VpqcException.DecryptionException.class,
                () -> Vpqc.open(other.secretKey(), sealed, b("one")));
        for (int i : new int[] {0, 6, 12, 500, sealed.length - 1}) {
            byte[] bad = sealed.clone();
            bad[i] ^= 1;
            assertThrows(VpqcException.class, () -> Vpqc.open(a.secretKey(), bad, b("one")));
        }
    }

    @Test
    void emptyInputs() {
        KeyPair k = Vpqc.generateEncryptionKeypair(Profile.STANDARD);
        byte[] sealed = Vpqc.seal(k.publicKey(), new byte[0], new byte[0]);
        assertEquals(0, Vpqc.open(k.secretKey(), sealed, new byte[0]).length);
    }

    @Test
    void signVerify() {
        for (Profile p : Profile.values()) {
            KeyPair k = Vpqc.generateSigningKeypair(p);
            byte[] sig = Vpqc.sign(k.secretKey(), b("msg"), b("app/v1"));
            Vpqc.verify(k.publicKey(), b("msg"), b("app/v1"), sig);
            assertThrows(VpqcException.VerificationException.class,
                    () -> Vpqc.verify(k.publicKey(), b("msg"), b("app/v2"), sig));
            assertThrows(VpqcException.VerificationException.class,
                    () -> Vpqc.verify(k.publicKey(), b("other"), b("app/v1"), sig));
        }
    }

    @Test
    void invalidInputs() {
        KeyPair sig = Vpqc.generateSigningKeypair(Profile.STANDARD);
        assertThrows(VpqcException.InvalidInputException.class,
                () -> Vpqc.seal(sig.publicKey(), b("x"), new byte[0]));
        assertThrows(VpqcException.InvalidInputException.class,
                () -> Vpqc.sign(sig.secretKey(), b("m"), new byte[256]));
        assertThrows(VpqcException.InvalidInputException.class,
                () -> Vpqc.seal(PublicKey.fromBytes(new byte[] {1, 2, 3}), b("x"), new byte[0]));
        VpqcException e = assertThrows(VpqcException.class,
                () -> Vpqc.seal(PublicKey.fromBytes(new byte[0]), b("x"), new byte[0]));
        assertTrue(e.code() != 0);
        assertFalse(e.getMessage().isEmpty());
    }

    @Test
    void keyText() {
        KeyPair k = Vpqc.generateEncryptionKeypair(Profile.STANDARD);
        String text = k.publicKey().toText();
        assertTrue(text.startsWith("-----BEGIN VPQC PUBLIC KEY-----"));
        assertEquals(k.publicKey(), PublicKey.fromText(text));
        SecretKey sk = SecretKey.fromText(k.secretKey().toText());
        byte[] sealed = Vpqc.seal(k.publicKey(), b("x"), new byte[0]);
        assertArrayEquals(b("x"), Vpqc.open(sk, sealed, new byte[0]));
        assertThrows(VpqcException.class, () -> PublicKey.fromText(k.secretKey().toText()));
    }

    @Test
    void secretKeyIsRedactedAndDestroyable() {
        KeyPair k = Vpqc.generateEncryptionKeypair(Profile.STANDARD);
        assertEquals("SecretKey(<redacted>)", k.secretKey().toString());
        byte[] sealed = Vpqc.seal(k.publicKey(), b("x"), new byte[0]);
        k.secretKey().destroy();
        assertTrue(k.secretKey().isDestroyed());
        assertThrows(IllegalStateException.class, () -> Vpqc.open(k.secretKey(), sealed, new byte[0]));
    }

    @Test
    void largeMessage() {
        KeyPair k = Vpqc.generateEncryptionKeypair(Profile.STANDARD);
        byte[] data = new byte[1 << 20];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) i;
        }
        assertArrayEquals(data, Vpqc.open(k.secretKey(), Vpqc.seal(k.publicKey(), data, new byte[0]), new byte[0]));
    }

    @Test
    void concurrentUse() throws Exception {
        KeyPair k = Vpqc.generateEncryptionKeypair(Profile.STANDARD);
        List<Thread> threads = new ArrayList<>();
        List<Throwable> failures = java.util.Collections.synchronizedList(new ArrayList<>());
        for (int t = 0; t < 8; t++) {
            final int id = t;
            Thread th = new Thread(() -> {
                try {
                    for (int i = 0; i < 20; i++) {
                        byte[] msg = b("message " + id + "/" + i);
                        byte[] sealed = Vpqc.seal(k.publicKey(), msg, new byte[0]);
                        assertArrayEquals(msg, Vpqc.open(k.secretKey(), sealed, new byte[0]));
                    }
                } catch (Throwable e) {
                    failures.add(e);
                }
            });
            threads.add(th);
            th.start();
        }
        for (Thread th : threads) {
            th.join();
        }
        assertTrue(failures.isEmpty(), failures.toString());
    }

    @Test
    void fileStreaming(@org.junit.jupiter.api.io.TempDir java.nio.file.Path dir) throws Exception {
        KeyPair k = Vpqc.generateEncryptionKeypair(Profile.STANDARD);
        byte[] data = new byte[3_000_000];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (i * 7);
        }
        java.nio.file.Path in = dir.resolve("in"), enc = dir.resolve("enc"), out = dir.resolve("out");
        java.nio.file.Files.write(in, data);
        assertEquals(data.length, Vpqc.encryptFile(k.publicKey(), in, enc, b("ctx")));
        assertEquals(data.length, Vpqc.decryptFile(k.secretKey(), enc, out, b("ctx")));
        assertArrayEquals(data, java.nio.file.Files.readAllBytes(out));
        assertThrows(VpqcException.DecryptionException.class,
                () -> Vpqc.decryptFile(k.secretKey(), enc, dir.resolve("bad"), b("other")));
        assertFalse(java.nio.file.Files.exists(dir.resolve("bad")));
        assertThrows(VpqcException.IoException.class,
                () -> Vpqc.encryptFile(k.publicKey(), dir.resolve("missing"), enc, new byte[0]));
    }
}
