// Dart driver for the interoperability suite. See interop/run.sh.
import 'dart:convert';
import 'dart:io';

import 'package:vpqc/vpqc.dart';

List<int> u(String s) => utf8.encode(s);
PublicKey pub(String path) => PublicKey.fromText(File(path).readAsStringSync());
SecretKey sec(String path) => SecretKey.fromText(File(path).readAsStringSync());
Profile prof(String name) => switch (name) {
      'standard' => Profile.standard,
      'fast-auth' => Profile.fastAuth,
      'cnsa2' => Profile.cnsa2,
      'high' => Profile.high,
      _ => throw ArgumentError('unknown profile $name'),
    };

void main(List<String> args) {
  final a = args.skip(1).toList();
  try {
    switch (args[0]) {
      case 'keygen': // keygen encrypt|sign PROFILE OUT_PREFIX
        final kp = a[0] == 'encrypt' ? Vpqc.generateEncryptionKeypair(prof(a[1])) : Vpqc.generateSigningKeypair(prof(a[1]));
        File('${a[2]}.pub').writeAsStringSync(kp.public.toText());
        File('${a[2]}.sec').writeAsStringSync(kp.secret.toText());
      case 'seal': // seal PUBFILE AAD IN OUT
        File(a[3]).writeAsBytesSync(Vpqc.seal(pub(a[0]), File(a[2]).readAsBytesSync(), aad: u(a[1])));
      case 'open': // open SECFILE AAD IN OUT
        File(a[3]).writeAsBytesSync(Vpqc.open(sec(a[0]), File(a[2]).readAsBytesSync(), aad: u(a[1])));
      case 'sign': // sign SECFILE CTX IN OUT
        File(a[3]).writeAsBytesSync(Vpqc.sign(sec(a[0]), File(a[2]).readAsBytesSync(), context: u(a[1])));
      case 'verify': // verify PUBFILE CTX SIG IN
        Vpqc.verify(pub(a[0]), File(a[3]).readAsBytesSync(), File(a[2]).readAsBytesSync(), context: u(a[1]));
      case 'encrypt-file': // encrypt-file PUBFILE AAD IN OUT
        Vpqc.encryptFile(pub(a[0]), a[2], a[3], aad: u(a[1]));
      case 'encrypt-file-multi': // encrypt-file-multi AAD IN OUT PUBFILE...
        Vpqc.encryptFileMulti(a.skip(3).map(pub).toList(), a[1], a[2], aad: u(a[0]));
      case 'rewrap-file': // rewrap-file SECFILE AAD IN OUT PUBFILE...
        Vpqc.rewrapFile(sec(a[0]), a.skip(4).map(pub).toList(), a[2], a[3], aad: u(a[1]));
      case 'decrypt-file': // decrypt-file SECFILE AAD IN OUT
        Vpqc.decryptFile(sec(a[0]), a[2], a[3], aad: u(a[1]));
      case 'protect': // protect SECFILE PASSPHRASE OUT
        File(a[2]).writeAsStringSync(sec(a[0]).toProtectedText(a[1], memoryKib: 8192));
      case 'unprotect': // unprotect PROTFILE PASSPHRASE OUT
        File(a[2]).writeAsStringSync(SecretKey.fromProtected(File(a[0]).readAsStringSync(), a[1]).toText());
      default:
        throw ArgumentError('unknown command ${args[0]}');
    }
  } on VpqcException catch (e) {
    stderr.writeln('dart-driver: ${e.message}');
    exit(1);
  } on ArgumentError catch (e) {
    stderr.writeln('dart-driver: $e');
    exit(1);
  } on FileSystemException catch (e) {
    stderr.writeln('dart-driver: $e');
    exit(1);
  }
}
