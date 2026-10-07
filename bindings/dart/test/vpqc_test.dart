import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:vpqc/vpqc.dart';

List<int> b(String s) => utf8.encode(s);

void main() {
  test('ABI version is at least 1.1', () {
    expect(Vpqc.abiVersion, greaterThanOrEqualTo((1 << 16) | 1));
  });

  test('encrypt round trip, all profiles', () {
    for (final p in Profile.values) {
      final k = Vpqc.generateEncryptionKeypair(p);
      final sealed = Vpqc.seal(k.public, b('secret'), aad: b('ctx'));
      expect(Vpqc.open(k.secret, sealed, aad: b('ctx')), b('secret'));
      expect(Vpqc.open(k.secret, Vpqc.seal(k.public, const []), aad: const []), isEmpty);
    }
  });

  test('wrong key, wrong context and tampering fail', () {
    final a = Vpqc.generateEncryptionKeypair();
    final other = Vpqc.generateEncryptionKeypair();
    final sealed = Vpqc.seal(a.public, b('x'), aad: b('ctx'));
    expect(() => Vpqc.open(other.secret, sealed, aad: b('ctx')), throwsA(isA<DecryptionException>()));
    expect(() => Vpqc.open(a.secret, sealed, aad: b('other')), throwsA(isA<DecryptionException>()));
    final bad = Uint8List.fromList(sealed)..[sealed.length - 1] ^= 1;
    expect(() => Vpqc.open(a.secret, bad, aad: b('ctx')), throwsA(isA<DecryptionException>()));
    expect(() => Vpqc.open(a.secret, [1, 2, 3]), throwsA(isA<InvalidInputException>()));
  });

  test('sign and verify, all profiles', () {
    for (final p in Profile.values) {
      final k = Vpqc.generateSigningKeypair(p);
      final sig = Vpqc.sign(k.secret, b('release'), context: b('app/v1'));
      Vpqc.verify(k.public, b('release'), sig, context: b('app/v1'));
      expect(() => Vpqc.verify(k.public, b('release'), sig, context: b('app/v2')),
          throwsA(isA<VerificationException>()));
      expect(Vpqc.isValid(k.public, b('tampered'), sig, context: b('app/v1')), isFalse);
      expect(Vpqc.isValid(k.public, b('release'), sig, context: b('app/v1')), isTrue);
    }
    final k = Vpqc.generateSigningKeypair();
    expect(() => Vpqc.sign(k.secret, b('m'), context: List.filled(256, 1)),
        throwsA(isA<InvalidInputException>()));
  });

  test('key text and secret key hygiene', () {
    final k = Vpqc.generateEncryptionKeypair();
    final text = k.public.toText();
    expect(text, startsWith('-----BEGIN VPQC PUBLIC KEY-----'));
    expect(PublicKey.fromText(text), k.public);
    final sk = SecretKey.fromText(k.secret.toText());
    expect(Vpqc.open(sk, Vpqc.seal(k.public, b('x'))), b('x'));
    expect(() => PublicKey.fromText(k.secret.toText()), throwsA(isA<InvalidInputException>()));
    expect(k.secret.toString(), 'SecretKey(<redacted>)');
    final copy = SecretKey.fromBytes(k.secret.toBytes())..destroy();
    expect(copy.toBytes, throwsStateError);
  });

  test('passphrase-protected secret keys', () {
    final k = Vpqc.generateEncryptionKeypair();
    final text = k.secret.toProtectedText('mật khẩu đủ dài', memoryKib: 8192);
    expect(text, startsWith('-----BEGIN VPQC PROTECTED SECRET KEY-----'));
    expect(SecretKey.isProtected(b(text)), isTrue);
    expect(SecretKey.isProtected(k.secret.toBytes()), isFalse);
    final back = SecretKey.fromProtected(text, 'mật khẩu đủ dài');
    expect(back.toBytes(), k.secret.toBytes());
    expect(Vpqc.open(back, Vpqc.seal(k.public, b('p'))), b('p'));
    expect(() => SecretKey.fromProtected(text, 'wrong'), throwsA(isA<DecryptionException>()));
    expect(() => k.secret.toProtectedText('x', memoryKib: 1024), throwsA(isA<InvalidInputException>()));
    expect(() => k.secret.toProtectedText(''), throwsA(isA<InvalidInputException>()));
  });

  test('files, several recipients and re-wrapping', () {
    final dir = Directory.systemTemp.createTempSync('vpqc-dart-');
    addTearDown(() => dir.deleteSync(recursive: true));
    String p(String n) => '${dir.path}/$n';
    final data = Uint8List.fromList(List.generate(300000, (i) => (i * 31) % 251));
    File(p('in')).writeAsBytesSync(data);

    final a = Vpqc.generateEncryptionKeypair();
    expect(Vpqc.encryptFile(a.public, p('in'), p('enc'), aad: b('ctx')), data.length);
    expect(Vpqc.decryptFile(a.secret, p('enc'), p('out'), aad: b('ctx')), data.length);
    expect(File(p('out')).readAsBytesSync(), data);
    expect(() => Vpqc.decryptFile(a.secret, p('enc'), p('bad'), aad: b('other')),
        throwsA(isA<DecryptionException>()));
    expect(File(p('bad')).existsSync(), isFalse);
    expect(() => Vpqc.encryptFile(a.public, p('missing'), p('x')), throwsA(isA<VpqcIoException>()));

    final bk = Vpqc.generateEncryptionKeypair(Profile.high);
    final c = Vpqc.generateEncryptionKeypair(Profile.cnsa2);
    Vpqc.encryptFileMulti([a.public, bk.public], p('in'), p('menc'), aad: b('team'));
    Vpqc.decryptFile(bk.secret, p('menc'), p('mout'), aad: b('team'));
    expect(File(p('mout')).readAsBytesSync(), data);
    expect(() => Vpqc.decryptFile(c.secret, p('menc'), p('mx'), aad: b('team')),
        throwsA(isA<DecryptionException>()));
    Vpqc.rewrapFile(a.secret, [bk.public, c.public], p('menc'), p('mre'), aad: b('team'));
    Vpqc.decryptFile(c.secret, p('mre'), p('mout2'), aad: b('team'));
    expect(File(p('mout2')).readAsBytesSync(), data);
    expect(() => Vpqc.decryptFile(a.secret, p('mre'), p('mx2'), aad: b('team')),
        throwsA(isA<DecryptionException>()));
    expect(() => Vpqc.encryptFileMulti([], p('in'), p('none')), throwsA(isA<InvalidInputException>()));
  });

  final cli = Platform.environment['VPQC_CLI'];
  test('interoperates with the CLI', () {
    final dir = Directory.systemTemp.createTempSync('vpqc-dart-cli-');
    addTearDown(() => dir.deleteSync(recursive: true));
    String run(List<String> args, String passphrase) {
      final r = Process.runSync(cli!, args,
          workingDirectory: dir.path,
          environment: {'VPQC_PASSPHRASE': passphrase, 'VPQC_PASSPHRASE_FILE': ''});
      expect(r.exitCode, 0, reason: 'vpqc $args: ${r.stderr}');
      return r.stdout as String;
    }

    run(['keygen', '--purpose', 'encrypt', '--out', 'e', '--passphrase', '--kdf-memory', '8'],
        'shared passphrase 2026');
    final sk = SecretKey.fromProtected(
        File('${dir.path}/e.vpqc-secret').readAsStringSync(), 'shared passphrase 2026');
    final pk = PublicKey.fromText(File('${dir.path}/e.pub').readAsStringSync());
    File('${dir.path}/m.txt').writeAsStringSync('from the cli');
    run(['seal', '--to', 'e.pub', '--aad', 'x', '-o', 'm.sealed', 'm.txt'], '');
    expect(Vpqc.open(sk, File('${dir.path}/m.sealed').readAsBytesSync(), aad: b('x')), b('from the cli'));
    File('${dir.path}/n.sealed').writeAsBytesSync(Vpqc.seal(pk, b('from dart'), aad: b('y')));
    File('${dir.path}/n.key')
        .writeAsStringSync(sk.toProtectedText('another passphrase 2026', memoryKib: 8192));
    expect(run(['open', '--key', 'n.key', '--aad', 'y', 'n.sealed'], 'another passphrase 2026'), 'from dart');
  }, skip: cli == null || cli.isEmpty ? 'set VPQC_CLI' : false);
}
