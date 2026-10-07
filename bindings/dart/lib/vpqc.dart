/// Post-quantum cryptography with safe defaults. Pre-release and unaudited: do not protect real
/// secrets with it yet.
///
/// ```dart
/// final keys = Vpqc.generateEncryptionKeypair();
/// final sealed = Vpqc.seal(keys.public, utf8.encode('secret'), aad: utf8.encode('ctx'));
/// final plain = Vpqc.open(keys.secret, sealed, aad: utf8.encode('ctx'));
/// ```
///
/// The native library (`libvpqc_ffi.so`, `libvpqc_ffi.dylib` or `vpqc_ffi.dll`) must be
/// loadable; set `VPQC_LIBRARY` to its path to use a specific build.
library;

import 'dart:convert';
import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'src/errors.dart';
import 'src/native.dart';

export 'src/errors.dart';

/// The algorithm selection of a key pair. Pick a profile, not an algorithm.
enum Profile {
  /// X-Wing (X25519 + ML-KEM-768) and Ed25519 + ML-DSA-65 composite.
  standard(1),

  /// X-Wing and classical Ed25519 signatures: short-lived authentication only.
  fastAuth(2),

  /// ML-KEM-1024 and ML-DSA-87 (CNSA 2.0).
  cnsa2(3),

  /// P-384 + ML-KEM-1024 hybrid and ECDSA-P384 + ML-DSA-87 composite, for long-lived data.
  high(4);

  const Profile(this.id);
  final int id;
}

const _empty = <int>[];

Uint8List _b(List<int> v) => v is Uint8List ? v : Uint8List.fromList(v);

bool _equal(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  var d = 0;
  for (var i = 0; i < a.length; i++) {
    d |= a[i] ^ b[i];
  }
  return d == 0;
}

String _text(Uint8List bytes) => utf8.decode(bytes);

/// An encoded public key. Safe to share.
final class PublicKey {
  PublicKey._(this._bytes);

  /// Wraps a binary-encoded public key (validated on use).
  factory PublicKey.fromBytes(List<int> bytes) => PublicKey._(Uint8List.fromList(bytes));

  /// Parses an armored text public key.
  factory PublicKey.fromText(String text) => PublicKey._(_fromText(1, text));

  final Uint8List _bytes;

  /// The binary encoding.
  Uint8List toBytes() => Uint8List.fromList(_bytes);

  /// Armored text ("-----BEGIN VPQC PUBLIC KEY-----").
  String toText() => _toText(1, _bytes);

  @override
  bool operator ==(Object other) => other is PublicKey && _equal(_bytes, other._bytes);

  @override
  int get hashCode => Object.hashAll(_bytes.take(32));
}

/// An encoded secret key. Never printed. [destroy] wipes this instance's copy (the Dart runtime
/// may still hold other copies made by its garbage collector).
final class SecretKey {
  SecretKey._(this._bytes);

  /// Wraps a binary-encoded secret key (validated on use).
  factory SecretKey.fromBytes(List<int> bytes) => SecretKey._(Uint8List.fromList(bytes));

  /// Parses an armored text secret key.
  factory SecretKey.fromText(String text) => SecretKey._(_fromText(2, text));

  /// Is [data] a protected secret key (armored text or binary)?
  static bool isProtected(List<int> data) => withBytes([_b(data)], (c) {
        return Native.instance.secretKeyIsProtected(c[0].ptr, c[0].length) == 1;
      });

  /// Decrypts a passphrase-protected key (Argon2id + XChaCha20-Poly1305, ADR-0013), as written by
  /// [toProtectedText], any other vpqc binding or `vpqc keygen --passphrase`.
  ///
  /// Throws [DecryptionException] for a wrong passphrase or a modified key.
  factory SecretKey.fromProtected(String text, String passphrase) {
    final n = Native.instance;
    final out = calloc<VpqcBuf>();
    try {
      final key = withBytes([utf8.encode(text), utf8.encode(passphrase)], (c) {
        n.check(n.secretKeyUnprotect(c[0].ptr, c[0].length, c[1].ptr, c[1].length, out));
        return n.take(out);
      }, secrets: {1});
      return SecretKey._(key);
    } finally {
      calloc.free(out);
    }
  }

  Uint8List? _bytes;

  Uint8List get _raw => _bytes ?? (throw StateError('secret key has been destroyed'));

  /// Armored text encrypted under [passphrase]. [memoryKib] is the Argon2id memory: 0 for the
  /// default (64 MiB), else 8192 to 1048576.
  String toProtectedText(String passphrase, {int memoryKib = 0}) {
    final n = Native.instance;
    final out = calloc<VpqcBuf>();
    try {
      return withBytes([_raw, utf8.encode(passphrase)], (c) {
        n.check(n.secretKeyProtect(c[0].ptr, c[0].length, c[1].ptr, c[1].length, memoryKib, out));
        return _text(n.take(out));
      }, secrets: {0, 1});
    } finally {
      calloc.free(out);
    }
  }

  /// The binary encoding. Unencrypted.
  Uint8List toBytes() => Uint8List.fromList(_raw);

  /// Armored text. Unencrypted.
  String toText() => _toText(2, _raw);

  /// Wipes this instance's copy of the key.
  void destroy() {
    _bytes?.fillRange(0, _bytes!.length, 0);
    _bytes = null;
  }

  @override
  String toString() => 'SecretKey(<redacted>)';
}

/// A generated key pair.
final class KeyPair {
  KeyPair(this.public, this.secret);
  final PublicKey public;
  final SecretKey secret;
}

Uint8List _fromText(int kind, String text) {
  final n = Native.instance;
  final out = calloc<VpqcBuf>();
  try {
    return withBytes([utf8.encode(text)], (c) {
      n.check(n.keyFromText(kind, c[0].ptr, c[0].length, out));
      return n.take(out);
    });
  } finally {
    calloc.free(out);
  }
}

String _toText(int kind, Uint8List key) {
  final n = Native.instance;
  final out = calloc<VpqcBuf>();
  try {
    return withBytes([key], (c) {
      n.check(n.keyToText(kind, c[0].ptr, c[0].length, out));
      return _text(n.take(out));
    }, secrets: {0});
  } finally {
    calloc.free(out);
  }
}

KeyPair _keygen(int Function(int, Pointer<VpqcBuf>, Pointer<VpqcBuf>) f, Profile p) {
  final n = Native.instance;
  final pub = calloc<VpqcBuf>();
  final sec = calloc<VpqcBuf>();
  try {
    n.check(f(p.id, pub, sec));
    return KeyPair(PublicKey._(n.take(pub)), SecretKey._(n.take(sec)));
  } finally {
    calloc.free(pub);
    calloc.free(sec);
  }
}

Uint8List _call3(
    int Function(Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<VpqcBuf>) f,
    Uint8List a,
    Uint8List b,
    Uint8List c,
    {Set<int> secrets = const {}}) {
  final n = Native.instance;
  final out = calloc<VpqcBuf>();
  try {
    return withBytes([a, b, c], (x) {
      n.check(f(x[0].ptr, x[0].length, x[1].ptr, x[1].length, x[2].ptr, x[2].length, out));
      return n.take(out);
    }, secrets: secrets);
  } finally {
    calloc.free(out);
  }
}

/// The package API.
abstract final class Vpqc {
  /// A key pair for [seal] / [open].
  static KeyPair generateEncryptionKeypair([Profile profile = Profile.standard]) =>
      _keygen(Native.instance.encryptionKeygen, profile);

  /// A key pair for [sign] / [verify].
  static KeyPair generateSigningKeypair([Profile profile = Profile.standard]) =>
      _keygen(Native.instance.signingKeygen, profile);

  /// Encrypts to a recipient. [aad] is authenticated context that [open] must receive again.
  static Uint8List seal(PublicKey recipient, List<int> plaintext, {List<int> aad = _empty}) =>
      _call3(Native.instance.seal, recipient._bytes, _b(plaintext), _b(aad));

  /// Decrypts a sealed message. Throws [DecryptionException] for a wrong key, wrong [aad] or any
  /// modification.
  static Uint8List open(SecretKey secret, List<int> sealed, {List<int> aad = _empty}) =>
      _call3(Native.instance.open, secret._raw, _b(sealed), _b(aad), secrets: {0});

  /// Signs under a mandatory domain-separation context of at most 255 bytes.
  static Uint8List sign(SecretKey secret, List<int> message, {required List<int> context}) =>
      _call3(Native.instance.sign, secret._raw, _b(message), _b(context), secrets: {0});

  /// Verifies a signature. Throws [VerificationException] if it is not valid.
  static void verify(PublicKey publicKey, List<int> message, List<int> signature,
      {required List<int> context}) {
    final n = Native.instance;
    withBytes([publicKey._bytes, _b(message), _b(context), _b(signature)], (x) {
      n.check(n.verify(
          x[0].ptr, x[0].length, x[1].ptr, x[1].length, x[2].ptr, x[2].length, x[3].ptr, x[3].length));
    });
  }

  /// Like [verify], but returns false instead of throwing for an invalid signature.
  static bool isValid(PublicKey publicKey, List<int> message, List<int> signature,
      {required List<int> context}) {
    try {
      verify(publicKey, message, signature, context: context);
      return true;
    } on VerificationException {
      return false;
    }
  }

  /// Encrypts a file of any size in constant memory; the output is replaced atomically. Returns
  /// the plaintext length.
  static int encryptFile(PublicKey recipient, String input, String output, {List<int> aad = _empty}) =>
      _file(Native.instance.encryptFile, recipient._bytes, _b(aad), input, output);

  /// Decrypts a file produced by [encryptFile] or [encryptFileMulti]. The output appears only if
  /// the whole stream verifies. Throws [DecryptionException] for a wrong key, wrong [aad] or
  /// tampering.
  static int decryptFile(SecretKey secret, String input, String output, {List<int> aad = _empty}) =>
      _file(Native.instance.decryptFile, secret._raw, _b(aad), input, output, secret: true);

  /// Encrypts a file for 1 to 32 recipients; each decrypts with [decryptFile] and their own secret
  /// key. The envelope format lets the recipients change later with [rewrapFile].
  static int encryptFileMulti(List<PublicKey> recipients, String input, String output,
      {List<int> aad = _empty}) {
    final n = Native.instance;
    final inPath = input.toNativeUtf8();
    final outPath = output.toNativeUtf8();
    final count = calloc<Uint64>();
    try {
      return _withKeys(recipients, (keys, lens) {
        return withBytes([_b(aad)], (a) {
          n.check(n.encryptFileMulti(
              keys, lens, recipients.length, a[0].ptr, a[0].length, inPath, outPath, count));
          return count.value;
        });
      });
    } finally {
      calloc.free(inPath);
      calloc.free(outPath);
      calloc.free(count);
    }
  }

  /// Changes the recipients of a multi-recipient file without re-encrypting it. [secret] must
  /// belong to a current recipient. Removing a recipient does not revoke what they already read.
  static int rewrapFile(SecretKey secret, List<PublicKey> recipients, String input, String output,
      {List<int> aad = _empty}) {
    final n = Native.instance;
    final inPath = input.toNativeUtf8();
    final outPath = output.toNativeUtf8();
    final count = calloc<Uint64>();
    try {
      return _withKeys(recipients, (keys, lens) {
        return withBytes([secret._raw, _b(aad)], (a) {
          n.check(n.rewrapFile(a[0].ptr, a[0].length, keys, lens, recipients.length, a[1].ptr, a[1].length,
              inPath, outPath, count));
          return count.value;
        }, secrets: {0});
      });
    } finally {
      calloc.free(inPath);
      calloc.free(outPath);
      calloc.free(count);
    }
  }

  /// The native ABI version (`major << 16 | minor`).
  static int get abiVersion => Native.instance.abiVersion();
}

int _file(
    int Function(Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Utf8>, Pointer<Utf8>, Pointer<Uint64>) f,
    Uint8List key,
    Uint8List aad,
    String input,
    String output,
    {bool secret = false}) {
  final inPath = input.toNativeUtf8();
  final outPath = output.toNativeUtf8();
  final count = calloc<Uint64>();
  try {
    return withBytes([key, aad], (c) {
      Native.instance.check(f(c[0].ptr, c[0].length, c[1].ptr, c[1].length, inPath, outPath, count));
      return count.value;
    }, secrets: secret ? {0} : const {});
  } finally {
    calloc.free(inPath);
    calloc.free(outPath);
    calloc.free(count);
  }
}

R _withKeys<R>(List<PublicKey> keys, R Function(Pointer<Pointer<Uint8>>, Pointer<IntPtr>) body) {
  return withBytes(keys.map((k) => k._bytes).toList(), (copies) {
    final ptrs = calloc<Pointer<Uint8>>(keys.isEmpty ? 1 : keys.length);
    final lens = calloc<IntPtr>(keys.isEmpty ? 1 : keys.length);
    try {
      for (var i = 0; i < keys.length; i++) {
        ptrs[i] = copies[i].ptr;
        lens[i] = copies[i].length;
      }
      return body(ptrs, lens);
    } finally {
      calloc.free(ptrs);
      calloc.free(lens);
    }
  });
}
