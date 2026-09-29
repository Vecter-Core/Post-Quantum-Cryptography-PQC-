package org.vecter.vpqc;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

/**
 * Bindings to the C ABI ({@code vpqc.h}) through the Foreign Function &amp; Memory API.
 *
 * <p>Only APIs that are identical in JDK 21 (preview) and JDK 22+ (final) are used.
 */
final class Native {
    static final int KEY_PUBLIC = 1;
    static final int KEY_SECRET = 2;

    private static final Linker LINKER = Linker.nativeLinker();
    private static final SymbolLookup LOOKUP = locate();

    /** struct vpqc_buf { uint8_t *ptr; size_t len; } */
    private static final MemoryLayout BUF =
            MemoryLayout.structLayout(ValueLayout.ADDRESS, ValueLayout.JAVA_LONG);

    private static final Map<String, MethodHandle> HANDLES = new HashMap<>();

    private Native() {}

    private static SymbolLookup locate() {
        String file = System.mapLibraryName("vpqc_ffi");
        String dir = System.getProperty("vpqc.library.path", System.getenv("VPQC_LIBRARY_PATH"));
        if (dir != null) {
            Path path = Path.of(dir).resolve(file);
            if (Files.isRegularFile(path)) {
                return SymbolLookup.libraryLookup(path, Arena.global());
            }
        }
        System.loadLibrary("vpqc_ffi");
        return SymbolLookup.loaderLookup();
    }

    private static synchronized MethodHandle handle(String name, FunctionDescriptor fd) {
        return HANDLES.computeIfAbsent(name, n -> {
            MemorySegment symbol = LOOKUP.find(n).orElseThrow(
                    () -> new UnsatisfiedLinkError("symbol not found in vpqc_ffi: " + n));
            return LINKER.downcallHandle(symbol, fd);
        });
    }

    private static final FunctionDescriptor DESC_KEYGEN = FunctionDescriptor.of(
            ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS);

    /** (ptr,len) x3 + out */
    private static final FunctionDescriptor DESC_CALL3 = FunctionDescriptor.of(
            ValueLayout.JAVA_INT,
            ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
            ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
            ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
            ValueLayout.ADDRESS);

    private static final FunctionDescriptor DESC_VERIFY = FunctionDescriptor.of(
            ValueLayout.JAVA_INT,
            ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
            ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
            ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
            ValueLayout.ADDRESS, ValueLayout.JAVA_LONG);

    private static final FunctionDescriptor DESC_KEYTEXT = FunctionDescriptor.of(
            ValueLayout.JAVA_INT,
            ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS);

    private static Throwable unwrap(Throwable t) {
        return t;
    }

    private static int invoke(MethodHandle h, Object... args) {
        try {
            return (int) h.invokeWithArguments(args);
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) {
            throw new IllegalStateException(unwrap(t));
        }
    }

    private static void invokeVoid(MethodHandle h, Object... args) {
        try {
            h.invokeWithArguments(args);
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) {
            throw new IllegalStateException(unwrap(t));
        }
    }

    /** Copies bytes into native memory owned by {@code arena}. */
    private static MemorySegment copyIn(Arena arena, byte[] bytes) {
        MemorySegment seg = arena.allocate(Math.max(bytes.length, 1));
        MemorySegment.copy(MemorySegment.ofArray(bytes), 0, seg, 0, bytes.length);
        return seg;
    }

    private static String message(int code) {
        try {
            MethodHandle h = handle("vpqc_error_message",
                    FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
            MemorySegment p = ((MemorySegment) h.invokeWithArguments(code)).reinterpret(256);
            int n = 0;
            while (n < 256 && p.get(ValueLayout.JAVA_BYTE, n) != 0) {
                n++;
            }
            byte[] b = new byte[n];
            MemorySegment.copy(p, ValueLayout.JAVA_BYTE, 0, b, 0, n);
            return new String(b, StandardCharsets.UTF_8);
        } catch (Throwable t) {
            return "error " + code;
        }
    }

    private static void check(int rc) {
        if (rc != 0) {
            throw VpqcException.of(rc, message(rc));
        }
    }

    /** Reads a vpqc_buf into a byte[] and frees (zeroizes) the native buffer. */
    private static byte[] take(MemorySegment buf) {
        MemorySegment ptr = buf.get(ValueLayout.ADDRESS, 0);
        long len = buf.get(ValueLayout.JAVA_LONG, 8);
        if (len > Integer.MAX_VALUE - 8) {
            throw new IllegalStateException("native buffer too large: " + len);
        }
        byte[] out = new byte[(int) len];
        if (len > 0) {
            MemorySegment.copy(ptr.reinterpret(len), ValueLayout.JAVA_BYTE, 0, out, 0, (int) len);
        }
        invokeVoid(handle("vpqc_buf_free", FunctionDescriptor.ofVoid(ValueLayout.ADDRESS)), buf);
        return out;
    }

    static int abiVersion() {
        return invoke(handle("vpqc_abi_version", FunctionDescriptor.of(ValueLayout.JAVA_INT)));
    }

    static KeyPair keygen(int profile, boolean encrypt) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment pub = arena.allocate(BUF);
            MemorySegment sec = arena.allocate(BUF);
            pub.fill((byte) 0);
            sec.fill((byte) 0);
            String fn = encrypt ? "vpqc_encryption_keygen" : "vpqc_signing_keygen";
            check(invoke(handle(fn, DESC_KEYGEN), profile, pub, sec));
            return new KeyPair(PublicKey.fromBytes(take(pub)), SecretKey.fromBytes(take(sec)));
        }
    }

    /** seal / open / sign share the shape (a, b, c) -> buffer. */
    static byte[] call3(String fn, byte[] a, byte[] b, byte[] c) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(BUF);
            out.fill((byte) 0);
            check(invoke(handle(fn, DESC_CALL3),
                    copyIn(arena, a), (long) a.length,
                    copyIn(arena, b), (long) b.length,
                    copyIn(arena, c), (long) c.length,
                    out));
            return take(out);
        }
    }

    static void verify(byte[] pk, byte[] message, byte[] context, byte[] signature) {
        try (Arena arena = Arena.ofConfined()) {
            check(invoke(handle("vpqc_verify", DESC_VERIFY),
                    copyIn(arena, pk), (long) pk.length,
                    copyIn(arena, message), (long) message.length,
                    copyIn(arena, context), (long) context.length,
                    copyIn(arena, signature), (long) signature.length));
        }
    }

    private static final FunctionDescriptor DESC_KEM_ENCAP = FunctionDescriptor.of(
            ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
            ValueLayout.ADDRESS, ValueLayout.ADDRESS);

    private static final FunctionDescriptor DESC_KEM_DECAP = FunctionDescriptor.of(
            ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
            ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS);

    /** Raw KEM encapsulation: returns {shared secret (32 bytes), ciphertext}. */
    static byte[][] kemEncapsulate(byte[] publicKey) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment ss = arena.allocate(32);
            MemorySegment out = arena.allocate(BUF);
            out.fill((byte) 0);
            check(invoke(handle("vpqc_kem_encapsulate", DESC_KEM_ENCAP),
                    copyIn(arena, publicKey), (long) publicKey.length, ss, out));
            byte[] secret = ss.toArray(ValueLayout.JAVA_BYTE);
            ss.fill((byte) 0);
            return new byte[][] {secret, take(out)};
        }
    }

    /** Raw KEM decapsulation: returns the 32-byte shared secret. */
    static byte[] kemDecapsulate(byte[] secretKey, byte[] ciphertext) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment ss = arena.allocate(32);
            MemorySegment sk = copyIn(arena, secretKey);
            check(invoke(handle("vpqc_kem_decapsulate", DESC_KEM_DECAP),
                    sk, (long) secretKey.length,
                    copyIn(arena, ciphertext), (long) ciphertext.length, ss));
            byte[] secret = ss.toArray(ValueLayout.JAVA_BYTE);
            ss.fill((byte) 0);
            sk.fill((byte) 0);
            return secret;
        }
    }

    private static final FunctionDescriptor DESC_FILE = FunctionDescriptor.of(
            ValueLayout.JAVA_INT,
            ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
            ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
            ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS);

    /** vpqc_encrypt_file / vpqc_decrypt_file. Returns the number of plaintext bytes. */
    static long file(String fn, byte[] key, byte[] aad, String input, String output) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment n = arena.allocate(ValueLayout.JAVA_LONG);
            MemorySegment k = copyIn(arena, key);
            try {
                check(invoke(handle(fn, DESC_FILE),
                        k, (long) key.length,
                        copyIn(arena, aad), (long) aad.length,
                        cString(arena, input), cString(arena, output), n));
            } finally {
                k.fill((byte) 0);
            }
            return n.get(ValueLayout.JAVA_LONG, 0);
        }
    }

    private static final FunctionDescriptor DESC_FILE_MULTI = FunctionDescriptor.of(
            ValueLayout.JAVA_INT,
            ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
            ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
            ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS);

    private static final FunctionDescriptor DESC_REWRAP = FunctionDescriptor.of(
            ValueLayout.JAVA_INT,
            ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
            ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
            ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
            ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS);

    /**
     * vpqc_encrypt_file_multi (secret == null) or vpqc_rewrap_file (secret = a current
     * recipient's key). Returns the number of plaintext / body bytes.
     */
    static long fileMulti(byte[] secret, java.util.List<byte[]> recipients, byte[] aad, String input, String output) {
        try (Arena arena = Arena.ofConfined()) {
            int count = recipients.size();
            MemorySegment ptrs = arena.allocate(ValueLayout.ADDRESS.byteSize() * Math.max(count, 1),
                    ValueLayout.ADDRESS.byteAlignment());
            MemorySegment lens = arena.allocate(ValueLayout.JAVA_LONG.byteSize() * Math.max(count, 1),
                    ValueLayout.JAVA_LONG.byteAlignment());
            for (int i = 0; i < count; i++) {
                byte[] key = recipients.get(i);
                ptrs.setAtIndex(ValueLayout.ADDRESS, i, copyIn(arena, key));
                lens.setAtIndex(ValueLayout.JAVA_LONG, i, key.length);
            }
            MemorySegment n = arena.allocate(ValueLayout.JAVA_LONG);
            MemorySegment in = cString(arena, input);
            MemorySegment out = cString(arena, output);
            if (secret == null) {
                check(invoke(handle("vpqc_encrypt_file_multi", DESC_FILE_MULTI),
                        ptrs, lens, (long) count, copyIn(arena, aad), (long) aad.length, in, out, n));
            } else {
                MemorySegment k = copyIn(arena, secret);
                try {
                    check(invoke(handle("vpqc_rewrap_file", DESC_REWRAP),
                            k, (long) secret.length, ptrs, lens, (long) count,
                            copyIn(arena, aad), (long) aad.length, in, out, n));
                } finally {
                    k.fill((byte) 0);
                }
            }
            return n.get(ValueLayout.JAVA_LONG, 0);
        }
    }

    private static MemorySegment cString(Arena arena, String s) {
        byte[] b = s.getBytes(StandardCharsets.UTF_8);
        MemorySegment seg = arena.allocate(b.length + 1L);
        MemorySegment.copy(MemorySegment.ofArray(b), 0, seg, 0, b.length);
        seg.set(ValueLayout.JAVA_BYTE, b.length, (byte) 0);
        return seg;
    }

    static String keyToText(int kind, byte[] key) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(BUF);
            out.fill((byte) 0);
            check(invoke(handle("vpqc_key_to_text", DESC_KEYTEXT),
                    kind, copyIn(arena, key), (long) key.length, out));
            return new String(take(out), StandardCharsets.UTF_8);
        }
    }

    private static final FunctionDescriptor DESC_PROTECT = FunctionDescriptor.of(
            ValueLayout.JAVA_INT,
            ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
            ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
            ValueLayout.JAVA_INT, ValueLayout.ADDRESS);

    private static final FunctionDescriptor DESC_UNPROTECT = FunctionDescriptor.of(
            ValueLayout.JAVA_INT,
            ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
            ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
            ValueLayout.ADDRESS);

    /** Protected secret key text (ABI 1.1). The passphrase copy in native memory is wiped. */
    static String protectSecretKey(byte[] key, byte[] passphrase, int memoryKib) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(BUF);
            out.fill((byte) 0);
            MemorySegment k = copyIn(arena, key);
            MemorySegment p = copyIn(arena, passphrase);
            try {
                check(invoke(handle("vpqc_secret_key_protect", DESC_PROTECT),
                        k, (long) key.length, p, (long) passphrase.length, memoryKib, out));
            } finally {
                k.fill((byte) 0);
                p.fill((byte) 0);
            }
            return new String(take(out), StandardCharsets.UTF_8);
        }
    }

    /** Binary secret key from a passphrase-protected one (ABI 1.1). */
    static byte[] unprotectSecretKey(byte[] data, byte[] passphrase) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(BUF);
            out.fill((byte) 0);
            MemorySegment p = copyIn(arena, passphrase);
            try {
                check(invoke(handle("vpqc_secret_key_unprotect", DESC_UNPROTECT),
                        copyIn(arena, data), (long) data.length, p, (long) passphrase.length, out));
            } finally {
                p.fill((byte) 0);
            }
            return take(out);
        }
    }

    static boolean isProtectedSecretKey(byte[] data) {
        try (Arena arena = Arena.ofConfined()) {
            return invoke(handle("vpqc_secret_key_is_protected", FunctionDescriptor.of(
                    ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG)),
                    copyIn(arena, data), (long) data.length) == 1;
        }
    }

    static byte[] keyFromText(int kind, String text) {
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(BUF);
            out.fill((byte) 0);
            check(invoke(handle("vpqc_key_from_text", DESC_KEYTEXT),
                    kind, copyIn(arena, bytes), (long) bytes.length, out));
            return take(out);
        }
    }
}
