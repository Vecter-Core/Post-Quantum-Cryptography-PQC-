using System;
using System.Security.Cryptography;
using System.Text;

namespace Vecter.Vpqc;

/// <summary>The algorithm selection of a key pair. Pick a profile, not an algorithm.</summary>
public enum Profile
{
    /// <summary>X-Wing (X25519 + ML-KEM-768) and Ed25519 + ML-DSA-65 composite.</summary>
    Standard = 1,
    /// <summary>X-Wing and classical Ed25519 signatures: short-lived authentication only.</summary>
    FastAuth = 2,
    /// <summary>ML-KEM-1024 and ML-DSA-87 (CNSA 2.0).</summary>
    Cnsa2 = 3,
    /// <summary>P-384 + ML-KEM-1024 hybrid and ECDSA-P384 + ML-DSA-87 composite, for long-lived data.</summary>
    High = 4,
}

/// <summary>An encoded public key. Safe to share.</summary>
public sealed class PublicKey : IEquatable<PublicKey>
{
    private readonly byte[] _bytes;

    private PublicKey(byte[] bytes) => _bytes = bytes;

    /// <summary>Wraps a binary-encoded public key (validated on use).</summary>
    public static PublicKey FromBytes(byte[] bytes) => new((byte[])bytes.Clone());

    /// <summary>Parses an armored text public key.</summary>
    public static PublicKey FromText(string text)
    {
        var t = Encoding.UTF8.GetBytes(text);
        Native.Check(Native.vpqc_key_from_text(1, t, Native.Len(t), out var buf));
        return new PublicKey(Native.Take(ref buf));
    }

    /// <summary>The binary encoding.</summary>
    public byte[] ToBytes() => (byte[])_bytes.Clone();

    /// <summary>Armored text ("-----BEGIN VPQC PUBLIC KEY-----").</summary>
    public string ToText()
    {
        Native.Check(Native.vpqc_key_to_text(1, _bytes, Native.Len(_bytes), out var buf));
        return Encoding.UTF8.GetString(Native.Take(ref buf));
    }

    internal byte[] Raw => _bytes;

    /// <inheritdoc/>
    public bool Equals(PublicKey? other) => other is not null && CryptographicOperations.FixedTimeEquals(_bytes, other._bytes);

    /// <inheritdoc/>
    public override bool Equals(object? obj) => Equals(obj as PublicKey);

    /// <inheritdoc/>
    public override int GetHashCode() => BitConverter.ToInt32(_bytes, Math.Max(0, _bytes.Length - 4));
}

/// <summary>
/// An encoded secret key. Never printed. <see cref="Dispose"/> wipes this instance's copy (the
/// runtime may still hold others made by the garbage collector).
/// </summary>
public sealed class SecretKey : IDisposable
{
    private byte[]? _bytes;

    private SecretKey(byte[] bytes) => _bytes = bytes;

    /// <summary>Wraps a binary-encoded secret key (validated on use).</summary>
    public static SecretKey FromBytes(byte[] bytes) => new((byte[])bytes.Clone());

    /// <summary>Parses an armored text secret key.</summary>
    public static SecretKey FromText(string text)
    {
        var t = Encoding.UTF8.GetBytes(text);
        try
        {
            Native.Check(Native.vpqc_key_from_text(2, t, Native.Len(t), out var buf));
            return new SecretKey(Native.Take(ref buf));
        }
        finally { CryptographicOperations.ZeroMemory(t); }
    }

    /// <summary>Is <paramref name="data"/> a protected secret key (armored text or binary)?</summary>
    public static bool IsProtected(byte[] data) => Native.vpqc_secret_key_is_protected(data, Native.Len(data)) == 1;

    /// <summary>
    /// Decrypts a passphrase-protected key (Argon2id + XChaCha20-Poly1305, ADR-0013), as written
    /// by <see cref="ToProtectedText"/>, any other vpqc binding or <c>vpqc keygen --passphrase</c>.
    /// </summary>
    /// <exception cref="DecryptionException">Wrong passphrase or modified key.</exception>
    public static SecretKey FromProtected(string text, ReadOnlySpan<char> passphrase)
    {
        var data = Encoding.UTF8.GetBytes(text);
        var pass = Utf8(passphrase);
        try
        {
            Native.Check(Native.vpqc_secret_key_unprotect(data, Native.Len(data), pass, Native.Len(pass), out var buf));
            return new SecretKey(Native.Take(ref buf));
        }
        finally { CryptographicOperations.ZeroMemory(pass); }
    }

    /// <summary>
    /// Armored text encrypted under a passphrase. <paramref name="memoryKib"/> is the Argon2id
    /// memory: 0 for the default (64 MiB), else 8192 to 1048576.
    /// </summary>
    public string ToProtectedText(ReadOnlySpan<char> passphrase, uint memoryKib = 0)
    {
        var pass = Utf8(passphrase);
        try
        {
            var raw = Raw;
            Native.Check(Native.vpqc_secret_key_protect(raw, Native.Len(raw), pass, Native.Len(pass), memoryKib, out var buf));
            return Encoding.UTF8.GetString(Native.Take(ref buf));
        }
        finally { CryptographicOperations.ZeroMemory(pass); }
    }

    /// <summary>The binary encoding. Unencrypted.</summary>
    public byte[] ToBytes() => (byte[])Raw.Clone();

    /// <summary>Armored text. Unencrypted.</summary>
    public string ToText()
    {
        var raw = Raw;
        Native.Check(Native.vpqc_key_to_text(2, raw, Native.Len(raw), out var buf));
        return Encoding.UTF8.GetString(Native.Take(ref buf));
    }

    internal byte[] Raw => _bytes ?? throw new ObjectDisposedException(nameof(SecretKey));

    private static byte[] Utf8(ReadOnlySpan<char> chars)
    {
        // No intermediate char[] copy: the only copy made here is the one that is wiped after use.
        var bytes = new byte[Encoding.UTF8.GetByteCount(chars)];
        Encoding.UTF8.GetBytes(chars, bytes);
        return bytes;
    }

    /// <summary>Wipes this instance's copy of the key.</summary>
    public void Dispose()
    {
        if (_bytes is not null) CryptographicOperations.ZeroMemory(_bytes);
        _bytes = null;
    }

    /// <summary>Never shows key material.</summary>
    public override string ToString() => "SecretKey(<redacted>)";
}

/// <summary>A generated key pair.</summary>
public sealed record KeyPair(PublicKey Public, SecretKey Secret);
