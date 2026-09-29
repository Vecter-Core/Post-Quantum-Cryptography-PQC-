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

    static String keyToText(int kind, byte[] key) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(BUF);
            out.fill((byte) 0);
            check(invoke(handle("vpqc_key_to_text", DESC_KEYTEXT),
                    kind, copyIn(arena, key), (long) key.length, out));
            return new String(take(out), StandardCharsets.UTF_8);
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
