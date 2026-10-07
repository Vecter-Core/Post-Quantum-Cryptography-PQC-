# vpqc (Dart)

Post-quantum cryptography with safe defaults. Native core in Rust through `dart:ffi`.
**Pre-release, unaudited: do not protect real secrets with it yet.**

```dart
import 'dart:convert';
import 'package:vpqc/vpqc.dart';

// Public-key encryption: hybrid X25519 + ML-KEM-768 (X-Wing) + ChaCha20-Poly1305
final keys = Vpqc.generateEncryptionKeypair(); // Profile.standard
final sealed = Vpqc.seal(keys.public, utf8.encode('secret'), aad: utf8.encode('invoice-42'));
final plain = Vpqc.open(keys.secret, sealed, aad: utf8.encode('invoice-42')); // DecryptionException if wrong

// Signatures: composite Ed25519 + ML-DSA-65 with a required context
final signer = Vpqc.generateSigningKeypair();
final sig = Vpqc.sign(signer.secret, utf8.encode('release.tar.gz'), context: utf8.encode('my-app/v1'));
Vpqc.verify(signer.public, utf8.encode('release.tar.gz'), sig, context: utf8.encode('my-app/v1'));

// Secret keys at rest (Argon2id + XChaCha20-Poly1305); readable by every vpqc binding and the CLI
File('signer.key').writeAsStringSync(signer.secret.toProtectedText('a long passphrase'));
final sk = SecretKey.fromProtected(File('signer.key').readAsStringSync(), 'a long passphrase');
```

Also: files of any size in constant memory (`encryptFile`, `decryptFile`), several recipients
(`encryptFileMulti`) and key rotation without re-encrypting (`rewrapFile`).

## Native library

Build `libvpqc_ffi` (or take it from a release archive) and make it loadable, or set
`VPQC_LIBRARY` to its path:

```sh
cargo build --release -p vpqc-ffi
VPQC_LIBRARY=$PWD/target/release/libvpqc_ffi.so VPQC_CLI=$PWD/target/release/vpqc \
  dart test bindings/dart
```

The package is not published to pub.dev while the project is pre-release (`publish_to: none`).
Flutter apps must bundle the native library for each platform they ship; that packaging is not
provided yet. Errors derive from `VpqcException` (`DecryptionException`, `VerificationException`,
`InvalidInputException`, `VpqcIoException`).
