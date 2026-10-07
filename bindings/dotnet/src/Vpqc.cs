using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Vecter.Vpqc;

/// <summary>
/// Post-quantum cryptography with safe defaults. Pre-release and unaudited: do not protect real
/// secrets with it yet.
/// <code>
/// var keys = Vpqc.GenerateEncryptionKeypair();
/// var sealed = Vpqc.Seal(keys.Public, Encoding.UTF8.GetBytes("secret"), Encoding.UTF8.GetBytes("ctx"));
/// var plain = Vpqc.Open(keys.Secret, sealed, Encoding.UTF8.GetBytes("ctx"));
/// </code>
/// </summary>
public static class Vpqc
{
    private static readonly byte[] Empty = [];

    /// <summary>A key pair for <see cref="Seal"/> / <see cref="Open"/>.</summary>
    public static KeyPair GenerateEncryptionKeypair(Profile profile = Profile.Standard)
    {
        Native.Check(Native.vpqc_encryption_keygen((int)profile, out var pub, out var sec));
        return new KeyPair(PublicKey.FromBytes(Native.Take(ref pub)), SecretKey.FromBytes(Native.Take(ref sec)));
    }

    /// <summary>A key pair for <see cref="Sign"/> / <see cref="Verify"/>.</summary>
    public static KeyPair GenerateSigningKeypair(Profile profile = Profile.Standard)
    {
        Native.Check(Native.vpqc_signing_keygen((int)profile, out var pub, out var sec));
        return new KeyPair(PublicKey.FromBytes(Native.Take(ref pub)), SecretKey.FromBytes(Native.Take(ref sec)));
    }

    /// <summary>Encrypts to a recipient. <paramref name="aad"/> is authenticated context that <see cref="Open"/> must receive again.</summary>
    public static byte[] Seal(PublicKey recipient, byte[] plaintext, byte[]? aad = null)
    {
        aad ??= Empty;
        Native.Check(Native.vpqc_seal(recipient.Raw, Native.Len(recipient.Raw), plaintext, Native.Len(plaintext), aad, Native.Len(aad), out var buf));
        return Native.Take(ref buf);
    }

    /// <summary>Decrypts a sealed message.</summary>
    /// <exception cref="DecryptionException">Wrong key, wrong <paramref name="aad"/> or any modification.</exception>
    public static byte[] Open(SecretKey secret, byte[] sealedMessage, byte[]? aad = null)
    {
        aad ??= Empty;
        var sk = secret.Raw;
        Native.Check(Native.vpqc_open(sk, Native.Len(sk), sealedMessage, Native.Len(sealedMessage), aad, Native.Len(aad), out var buf));
        return Native.Take(ref buf);
    }

    /// <summary>Signs under a mandatory domain-separation context of at most 255 bytes.</summary>
    public static byte[] Sign(SecretKey secret, byte[] message, byte[] context)
    {
        var sk = secret.Raw;
        Native.Check(Native.vpqc_sign(sk, Native.Len(sk), message, Native.Len(message), context, Native.Len(context), out var buf));
        return Native.Take(ref buf);
    }

    /// <summary>Verifies a signature.</summary>
    /// <exception cref="VerificationException">The signature is not valid.</exception>
    public static void Verify(PublicKey publicKey, byte[] message, byte[] context, byte[] signature) =>
        Native.Check(Native.vpqc_verify(publicKey.Raw, Native.Len(publicKey.Raw), message, Native.Len(message),
            context, Native.Len(context), signature, Native.Len(signature)));

    /// <summary>Like <see cref="Verify"/>, but returns false instead of throwing for an invalid signature.</summary>
    public static bool IsValid(PublicKey publicKey, byte[] message, byte[] context, byte[] signature)
    {
        try { Verify(publicKey, message, context, signature); return true; }
        catch (VerificationException) { return false; }
    }

    /// <summary>Encrypts a file of any size in constant memory; the output is replaced atomically. Returns the plaintext length.</summary>
    public static ulong EncryptFile(PublicKey recipient, string input, string output, byte[]? aad = null)
    {
        aad ??= Empty;
        Native.Check(Native.vpqc_encrypt_file(recipient.Raw, Native.Len(recipient.Raw), aad, Native.Len(aad),
            Native.CString(input), Native.CString(output), out var n));
        return n;
    }

    /// <summary>
    /// Encrypts a file for 1 to 32 recipients; each decrypts with <see cref="DecryptFile"/> and their
    /// own secret key. The envelope format lets the recipients change later with <see cref="RewrapFile"/>.
    /// </summary>
    public static ulong EncryptFileMulti(IEnumerable<PublicKey> recipients, string input, string output, byte[]? aad = null)
    {
        aad ??= Empty;
        var keys = recipients.Select(r => r.Raw).ToArray();
        return Native.WithKeys(keys, (ptrs, lens) =>
        {
            Native.Check(Native.vpqc_encrypt_file_multi(ptrs, lens, (nuint)keys.Length, aad, Native.Len(aad),
                Native.CString(input), Native.CString(output), out var n));
            return n;
        });
    }

    /// <summary>
    /// Changes the recipients of a multi-recipient file without re-encrypting it. <paramref name="secret"/>
    /// must belong to a current recipient. Removing a recipient does not revoke what they already read.
    /// </summary>
    /// <exception cref="DecryptionException"><paramref name="secret"/> is not a current recipient.</exception>
    public static ulong RewrapFile(SecretKey secret, IEnumerable<PublicKey> recipients, string input, string output, byte[]? aad = null)
    {
        aad ??= Empty;
        var keys = recipients.Select(r => r.Raw).ToArray();
        var sk = secret.Raw;
        return Native.WithKeys(keys, (ptrs, lens) =>
        {
            Native.Check(Native.vpqc_rewrap_file(sk, Native.Len(sk), ptrs, lens, (nuint)keys.Length, aad, Native.Len(aad),
                Native.CString(input), Native.CString(output), out var n));
            return n;
        });
    }

    /// <summary>Decrypts a file produced by <see cref="EncryptFile"/>. The output appears only if the whole stream verifies.</summary>
    /// <exception cref="DecryptionException">Wrong key, wrong <paramref name="aad"/> or tampering.</exception>
    public static ulong DecryptFile(SecretKey secret, string input, string output, byte[]? aad = null)
    {
        aad ??= Empty;
        var sk = secret.Raw;
        Native.Check(Native.vpqc_decrypt_file(sk, Native.Len(sk), aad, Native.Len(aad),
            Native.CString(input), Native.CString(output), out var n));
        return n;
    }

    /// <summary>The native ABI version (<c>major &lt;&lt; 16 | minor</c>).</summary>
    public static uint AbiVersion() => Native.vpqc_abi_version();

    /// <summary>UTF-8 bytes of a string, a convenience for contexts and associated data.</summary>
    public static byte[] Utf8(string text) => Encoding.UTF8.GetBytes(text);
}
