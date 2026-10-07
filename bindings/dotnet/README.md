# Vecter.Vpqc (.NET)

Post-quantum cryptography with safe defaults. Native core in Rust, called through the C ABI
(P/Invoke). **Pre-release, unaudited: do not protect real secrets with it yet.** Target: .NET 8.

```csharp
using Vecter.Vpqc;

// Public-key encryption: hybrid X25519 + ML-KEM-768 (X-Wing) + ChaCha20-Poly1305
var keys = Vpqc.GenerateEncryptionKeypair();                       // Profile.Standard
var sealedMsg = Vpqc.Seal(keys.Public, Vpqc.Utf8("secret"), Vpqc.Utf8("invoice-42"));
var plain = Vpqc.Open(keys.Secret, sealedMsg, Vpqc.Utf8("invoice-42")); // DecryptionException if wrong

// Signatures: composite Ed25519 + ML-DSA-65 with a required context
var signer = Vpqc.GenerateSigningKeypair();
var sig = Vpqc.Sign(signer.Secret, Vpqc.Utf8("release.tar.gz"), Vpqc.Utf8("my-app/release-v1"));
Vpqc.Verify(signer.Public, Vpqc.Utf8("release.tar.gz"), Vpqc.Utf8("my-app/release-v1"), sig);

// Large files: constant memory, several recipients, key rotation without re-encrypting
Vpqc.EncryptFileMulti([alice.Public, recovery.Public], "backup.tar", "backup.tar.vpqc");
Vpqc.RewrapFile(alice.Secret, [bob.Public, recovery.Public], "backup.tar.vpqc", "backup2.vpqc");

// Secret keys at rest: Argon2id + XChaCha20-Poly1305, readable by every vpqc binding and the CLI
File.WriteAllText("signer.key", signer.Secret.ToProtectedText("a long passphrase"));
using var sk = SecretKey.FromProtected(File.ReadAllText("signer.key"), "a long passphrase");
```

Errors derive from `VpqcException`: `DecryptionException`, `VerificationException`,
`InvalidInputException`, `VpqcIoException`. `SecretKey` is `IDisposable` (wipes its copy), never
prints, and the managed runtime cannot guarantee that no other copy remains in memory.

## Native library

The NuGet package carries the native library for linux-x64/arm64, osx-x64/arm64 and win-x64
under `runtimes/<rid>/native`; .NET finds it without configuration. To use another build, set
`VPQC_LIBRARY` to the file (`libvpqc_ffi.so`, `libvpqc_ffi.dylib` or `vpqc_ffi.dll`).

## Build and test from source

```sh
cargo build --release -p vpqc-ffi
VPQC_LIBRARY=$PWD/target/release/libvpqc_ffi.so VPQC_CLI=$PWD/target/release/vpqc \
  dotnet test bindings/dotnet/tests -c Release
```
