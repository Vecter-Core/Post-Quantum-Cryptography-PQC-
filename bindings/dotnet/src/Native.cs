using System;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

namespace Vecter.Vpqc;

internal static class Native
{
    private const string Lib = "vpqc_ffi";

    [StructLayout(LayoutKind.Sequential)]
    internal struct Buf
    {
        public IntPtr Ptr;
        public nuint Len;
    }

    static Native()
    {
        // VPQC_LIBRARY names the library file explicitly; otherwise the platform default name
        // (libvpqc_ffi.so, libvpqc_ffi.dylib, vpqc_ffi.dll) is searched next to the assembly and
        // on the usual paths.
        NativeLibrary.SetDllImportResolver(typeof(Native).Assembly, (name, assembly, path) =>
        {
            if (name != Lib) return IntPtr.Zero;
            var explicitPath = Environment.GetEnvironmentVariable("VPQC_LIBRARY");
            return string.IsNullOrEmpty(explicitPath) ? IntPtr.Zero : NativeLibrary.Load(explicitPath);
        });
    }

    [DllImport(Lib)] internal static extern uint vpqc_abi_version();
    [DllImport(Lib)] private static extern IntPtr vpqc_error_message(int code);
    [DllImport(Lib)] internal static extern void vpqc_buf_free(ref Buf buf);
    [DllImport(Lib)] internal static extern int vpqc_encryption_keygen(int profile, out Buf pub, out Buf sec);
    [DllImport(Lib)] internal static extern int vpqc_signing_keygen(int profile, out Buf pub, out Buf sec);

    [DllImport(Lib)]
    internal static extern int vpqc_seal(byte[] pk, nuint pkLen, byte[] msg, nuint msgLen, byte[] aad, nuint aadLen, out Buf output);
    [DllImport(Lib)]
    internal static extern int vpqc_open(byte[] sk, nuint skLen, byte[] sealedMsg, nuint sealedLen, byte[] aad, nuint aadLen, out Buf output);
    [DllImport(Lib)]
    internal static extern int vpqc_sign(byte[] sk, nuint skLen, byte[] msg, nuint msgLen, byte[] ctx, nuint ctxLen, out Buf output);
    [DllImport(Lib)]
    internal static extern int vpqc_verify(byte[] pk, nuint pkLen, byte[] msg, nuint msgLen, byte[] ctx, nuint ctxLen, byte[] sig, nuint sigLen);

    [DllImport(Lib)] internal static extern int vpqc_key_to_text(int kind, byte[] key, nuint keyLen, out Buf output);
    [DllImport(Lib)] internal static extern int vpqc_key_from_text(int kind, byte[] text, nuint textLen, out Buf output);

    [DllImport(Lib)]
    internal static extern int vpqc_secret_key_protect(byte[] sk, nuint skLen, byte[] pass, nuint passLen, uint memoryKib, out Buf output);
    [DllImport(Lib)]
    internal static extern int vpqc_secret_key_unprotect(byte[] data, nuint dataLen, byte[] pass, nuint passLen, out Buf output);
    [DllImport(Lib)] internal static extern int vpqc_secret_key_is_protected(byte[] data, nuint dataLen);

    [DllImport(Lib)]
    internal static extern int vpqc_encrypt_file(byte[] pk, nuint pkLen, byte[] aad, nuint aadLen, byte[] input, byte[] output, out ulong n);
    [DllImport(Lib)]
    internal static extern int vpqc_decrypt_file(byte[] sk, nuint skLen, byte[] aad, nuint aadLen, byte[] input, byte[] output, out ulong n);
    [DllImport(Lib)]
    internal static extern int vpqc_encrypt_file_multi(IntPtr[] pks, nuint[] pkLens, nuint count, byte[] aad, nuint aadLen, byte[] input, byte[] output, out ulong n);
    [DllImport(Lib)]
    internal static extern int vpqc_rewrap_file(byte[] sk, nuint skLen, IntPtr[] pks, nuint[] pkLens, nuint count, byte[] aad, nuint aadLen, byte[] input, byte[] output, out ulong n);

    internal static void Check(int rc)
    {
        if (rc == 0) return;
        var msg = Marshal.PtrToStringUTF8(vpqc_error_message(rc)) ?? "vpqc error";
        throw VpqcException.FromCode(rc, msg);
    }

    /// <summary>Copies a native buffer into a managed array and frees (zeroizes) it.</summary>
    internal static byte[] Take(ref Buf buf)
    {
        var data = new byte[(int)buf.Len];
        if (buf.Len > 0) Marshal.Copy(buf.Ptr, data, 0, data.Length);
        vpqc_buf_free(ref buf);
        return data;
    }

    internal static nuint Len(byte[] b) => (nuint)b.Length;

    /// <summary>NUL-terminated UTF-8, as the file functions expect for paths.</summary>
    internal static byte[] CString(string s)
    {
        var bytes = new byte[Encoding.UTF8.GetByteCount(s) + 1];
        Encoding.UTF8.GetBytes(s, 0, s.Length, bytes, 0);
        return bytes;
    }

    /// <summary>Pins each key for the duration of a multi-recipient call.</summary>
    internal static T WithKeys<T>(byte[][] keys, Func<IntPtr[], nuint[], T> call)
    {
        var handles = new GCHandle[keys.Length];
        try
        {
            var ptrs = new IntPtr[keys.Length];
            var lens = new nuint[keys.Length];
            for (var i = 0; i < keys.Length; i++)
            {
                handles[i] = GCHandle.Alloc(keys[i], GCHandleType.Pinned);
                ptrs[i] = handles[i].AddrOfPinnedObject();
                lens[i] = (nuint)keys[i].Length;
            }
            return call(ptrs, lens);
        }
        finally
        {
            foreach (var h in handles) if (h.IsAllocated) h.Free();
        }
    }
}
