using System;

namespace Vecter.Vpqc;

/// <summary>A failure reported by the native library; <see cref="Code"/> is its status code.</summary>
public class VpqcException : Exception
{
    /// <summary>The native status code (see <c>vpqc.h</c>).</summary>
    public int Code { get; }

    /// <summary>Creates an exception.</summary>
    public VpqcException(string message, int code) : base(message) => Code = code;

    internal static VpqcException FromCode(int code, string message) => code switch
    {
        8 => new DecryptionException(message, code),
        9 => new VerificationException(message, code),
        1 or 3 or 4 or 5 or 6 or 10 => new InvalidInputException(message, code),
        11 => new VpqcIoException(message, code),
        _ => new VpqcException(message, code),
    };
}

/// <summary>Wrong key, wrong context, or modified data. Deliberately not more specific.</summary>
public sealed class DecryptionException(string message, int code) : VpqcException(message, code);

/// <summary>The signature is not valid for this key, message and context.</summary>
public sealed class VerificationException(string message, int code) : VpqcException(message, code);

/// <summary>A key, envelope or argument is malformed or of the wrong kind.</summary>
public sealed class InvalidInputException(string message, int code) : VpqcException(message, code);

/// <summary>An operating-system I/O error (file not found, permission denied, ...).</summary>
public sealed class VpqcIoException(string message, int code) : VpqcException(message, code);
