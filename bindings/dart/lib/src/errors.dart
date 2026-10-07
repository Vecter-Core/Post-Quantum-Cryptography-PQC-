/// A failure reported by the native library; [code] is its status code (see `vpqc.h`).
class VpqcException implements Exception {
  VpqcException(this.message, this.code);

  final String message;
  final int code;

  static VpqcException fromCode(int code, String message) => switch (code) {
        8 => DecryptionException(message, code),
        9 => VerificationException(message, code),
        1 || 3 || 4 || 5 || 6 || 10 => InvalidInputException(message, code),
        11 => VpqcIoException(message, code),
        _ => VpqcException(message, code),
      };

  @override
  String toString() => 'VpqcException($code): $message';
}

/// Wrong key, wrong context, or modified data. Deliberately not more specific.
final class DecryptionException extends VpqcException {
  DecryptionException(super.message, super.code);
}

/// The signature is not valid for this key, message and context.
final class VerificationException extends VpqcException {
  VerificationException(super.message, super.code);
}

/// A key, envelope or argument is malformed or of the wrong kind.
final class InvalidInputException extends VpqcException {
  InvalidInputException(super.message, super.code);
}

/// An operating-system I/O error (file not found, permission denied, ...).
final class VpqcIoException extends VpqcException {
  VpqcIoException(super.message, super.code);
}
