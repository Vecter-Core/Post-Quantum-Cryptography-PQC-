import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'errors.dart';

/// `vpqc_buf { uint8_t *ptr; size_t len; }`
final class VpqcBuf extends Struct {
  external Pointer<Uint8> ptr;
  @Size()
  external int len;
}

DynamicLibrary _open() {
  final explicit = Platform.environment['VPQC_LIBRARY'];
  if (explicit != null && explicit.isNotEmpty) return DynamicLibrary.open(explicit);
  if (Platform.isMacOS || Platform.isIOS) return DynamicLibrary.open('libvpqc_ffi.dylib');
  if (Platform.isWindows) return DynamicLibrary.open('vpqc_ffi.dll');
  return DynamicLibrary.open('libvpqc_ffi.so');
}

// size_t and the pointer-sized integer have the same width on every platform Dart supports.
typedef FfiCall3C = Int32 Function(
    Pointer<Uint8>, IntPtr, Pointer<Uint8>, IntPtr, Pointer<Uint8>, IntPtr, Pointer<VpqcBuf>);
typedef FfiCall3 = int Function(
    Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<VpqcBuf>);
typedef FfiKeygenC = Int32 Function(Int32, Pointer<VpqcBuf>, Pointer<VpqcBuf>);
typedef FfiKeygen = int Function(int, Pointer<VpqcBuf>, Pointer<VpqcBuf>);
typedef FfiVerifyC = Int32 Function(
    Pointer<Uint8>, IntPtr, Pointer<Uint8>, IntPtr, Pointer<Uint8>, IntPtr, Pointer<Uint8>, IntPtr);
typedef FfiVerify = int Function(
    Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int);
typedef FfiKeyTextC = Int32 Function(Int32, Pointer<Uint8>, IntPtr, Pointer<VpqcBuf>);
typedef FfiKeyText = int Function(int, Pointer<Uint8>, int, Pointer<VpqcBuf>);
typedef FfiProtectC = Int32 Function(
    Pointer<Uint8>, IntPtr, Pointer<Uint8>, IntPtr, Uint32, Pointer<VpqcBuf>);
typedef FfiProtect = int Function(Pointer<Uint8>, int, Pointer<Uint8>, int, int, Pointer<VpqcBuf>);
typedef FfiUnprotectC = Int32 Function(Pointer<Uint8>, IntPtr, Pointer<Uint8>, IntPtr, Pointer<VpqcBuf>);
typedef FfiUnprotect = int Function(Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<VpqcBuf>);
typedef FfiIsProtectedC = Int32 Function(Pointer<Uint8>, IntPtr);
typedef FfiIsProtected = int Function(Pointer<Uint8>, int);
typedef FfiFileC = Int32 Function(
    Pointer<Uint8>, IntPtr, Pointer<Uint8>, IntPtr, Pointer<Utf8>, Pointer<Utf8>, Pointer<Uint64>);
typedef FfiFile = int Function(
    Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Utf8>, Pointer<Utf8>, Pointer<Uint64>);
typedef FfiFileMultiC = Int32 Function(Pointer<Pointer<Uint8>>, Pointer<IntPtr>, IntPtr, Pointer<Uint8>,
    IntPtr, Pointer<Utf8>, Pointer<Utf8>, Pointer<Uint64>);
typedef FfiFileMulti = int Function(Pointer<Pointer<Uint8>>, Pointer<IntPtr>, int, Pointer<Uint8>, int,
    Pointer<Utf8>, Pointer<Utf8>, Pointer<Uint64>);
typedef FfiRewrapC = Int32 Function(Pointer<Uint8>, IntPtr, Pointer<Pointer<Uint8>>, Pointer<IntPtr>, IntPtr,
    Pointer<Uint8>, IntPtr, Pointer<Utf8>, Pointer<Utf8>, Pointer<Uint64>);
typedef FfiRewrap = int Function(Pointer<Uint8>, int, Pointer<Pointer<Uint8>>, Pointer<IntPtr>, int,
    Pointer<Uint8>, int, Pointer<Utf8>, Pointer<Utf8>, Pointer<Uint64>);

/// The native entry points. Loaded lazily, so that merely importing the package does not need
/// the library.
final class Native {
  Native._() {
    final l = _open();
    abiVersion = l.lookupFunction<Uint32 Function(), int Function()>('vpqc_abi_version');
    _errorMessage =
        l.lookupFunction<Pointer<Utf8> Function(Int32), Pointer<Utf8> Function(int)>('vpqc_error_message');
    bufFree =
        l.lookupFunction<Void Function(Pointer<VpqcBuf>), void Function(Pointer<VpqcBuf>)>('vpqc_buf_free');
    encryptionKeygen = l.lookupFunction<FfiKeygenC, FfiKeygen>('vpqc_encryption_keygen');
    signingKeygen = l.lookupFunction<FfiKeygenC, FfiKeygen>('vpqc_signing_keygen');
    seal = l.lookupFunction<FfiCall3C, FfiCall3>('vpqc_seal');
    open = l.lookupFunction<FfiCall3C, FfiCall3>('vpqc_open');
    sign = l.lookupFunction<FfiCall3C, FfiCall3>('vpqc_sign');
    verify = l.lookupFunction<FfiVerifyC, FfiVerify>('vpqc_verify');
    keyToText = l.lookupFunction<FfiKeyTextC, FfiKeyText>('vpqc_key_to_text');
    keyFromText = l.lookupFunction<FfiKeyTextC, FfiKeyText>('vpqc_key_from_text');
    secretKeyProtect = l.lookupFunction<FfiProtectC, FfiProtect>('vpqc_secret_key_protect');
    secretKeyUnprotect = l.lookupFunction<FfiUnprotectC, FfiUnprotect>('vpqc_secret_key_unprotect');
    secretKeyIsProtected = l.lookupFunction<FfiIsProtectedC, FfiIsProtected>('vpqc_secret_key_is_protected');
    encryptFile = l.lookupFunction<FfiFileC, FfiFile>('vpqc_encrypt_file');
    decryptFile = l.lookupFunction<FfiFileC, FfiFile>('vpqc_decrypt_file');
    encryptFileMulti = l.lookupFunction<FfiFileMultiC, FfiFileMulti>('vpqc_encrypt_file_multi');
    rewrapFile = l.lookupFunction<FfiRewrapC, FfiRewrap>('vpqc_rewrap_file');
  }

  static final Native instance = Native._();

  late final int Function() abiVersion;
  late final Pointer<Utf8> Function(int) _errorMessage;
  late final void Function(Pointer<VpqcBuf>) bufFree;
  late final FfiKeygen encryptionKeygen;
  late final FfiKeygen signingKeygen;
  late final FfiCall3 seal;
  late final FfiCall3 open;
  late final FfiCall3 sign;
  late final FfiVerify verify;
  late final FfiKeyText keyToText;
  late final FfiKeyText keyFromText;
  late final FfiProtect secretKeyProtect;
  late final FfiUnprotect secretKeyUnprotect;
  late final FfiIsProtected secretKeyIsProtected;
  late final FfiFile encryptFile;
  late final FfiFile decryptFile;
  late final FfiFileMulti encryptFileMulti;
  late final FfiRewrap rewrapFile;

  /// Throws the matching [VpqcException] unless [rc] is 0.
  void check(int rc) {
    if (rc == 0) return;
    throw VpqcException.fromCode(rc, _errorMessage(rc).toDartString());
  }

  /// Copies a native buffer into Dart memory and frees (zeroizes) it.
  Uint8List take(Pointer<VpqcBuf> buf) {
    final n = buf.ref.len;
    final out = n == 0 ? Uint8List(0) : Uint8List.fromList(buf.ref.ptr.asTypedList(n));
    bufFree(buf);
    return out;
  }
}

/// A native copy of Dart bytes, freed (and zeroed when [secret]) by [free]. Empty input is a
/// null pointer with length 0, which the ABI allows.
final class NativeBytes {
  NativeBytes(Uint8List data, {this.secret = false})
      : length = data.length,
        ptr = data.isEmpty ? nullptr : calloc<Uint8>(data.length) {
    if (data.isNotEmpty) ptr.asTypedList(data.length).setAll(0, data);
  }

  final Pointer<Uint8> ptr;
  final int length;
  final bool secret;

  void free() {
    if (ptr == nullptr) return;
    if (secret) ptr.asTypedList(length).fillRange(0, length, 0);
    calloc.free(ptr);
  }
}

/// Runs [body] with native copies of [inputs] and frees them afterwards.
R withBytes<R>(List<Uint8List> inputs, R Function(List<NativeBytes>) body, {Set<int> secrets = const {}}) {
  final copies = <NativeBytes>[];
  try {
    for (var i = 0; i < inputs.length; i++) {
      copies.add(NativeBytes(inputs[i], secret: secrets.contains(i)));
    }
    return body(copies);
  } finally {
    for (final c in copies) {
      c.free();
    }
  }
}
