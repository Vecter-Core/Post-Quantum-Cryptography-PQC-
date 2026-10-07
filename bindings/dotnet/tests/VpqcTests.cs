using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using Vecter.Vpqc;
using Xunit;

namespace Vecter.Vpqc.Tests;

public class VpqcTests
{
    private static byte[] B(string s) => Encoding.UTF8.GetBytes(s);

    private static readonly Profile[] Profiles = [Profile.Standard, Profile.FastAuth, Profile.Cnsa2, Profile.High];

    [Fact]
    public void AbiVersionIsAtLeast1_1() => Assert.True(Vpqc.AbiVersion() >= ((1u << 16) | 1));

    [Fact]
    public void EncryptRoundTripAllProfiles()
    {
        foreach (var p in Profiles)
        {
            var keys = Vpqc.GenerateEncryptionKeypair(p);
            var sealedMsg = Vpqc.Seal(keys.Public, B("secret"), B("ctx"));
            Assert.Equal(B("secret"), Vpqc.Open(keys.Secret, sealedMsg, B("ctx")));
            Assert.Equal(B(""), Vpqc.Open(keys.Secret, Vpqc.Seal(keys.Public, [], null), null));
        }
    }

    [Fact]
    public void WrongKeyContextAndTamperingFail()
    {
        var a = Vpqc.GenerateEncryptionKeypair();
        var b = Vpqc.GenerateEncryptionKeypair();
        var sealedMsg = Vpqc.Seal(a.Public, B("x"), B("ctx"));
        Assert.Throws<DecryptionException>(() => Vpqc.Open(b.Secret, sealedMsg, B("ctx")));
        Assert.Throws<DecryptionException>(() => Vpqc.Open(a.Secret, sealedMsg, B("other")));
        var bad = (byte[])sealedMsg.Clone();
        bad[^1] ^= 1;
        Assert.Throws<DecryptionException>(() => Vpqc.Open(a.Secret, bad, B("ctx")));
        Assert.Throws<InvalidInputException>(() => Vpqc.Open(a.Secret, [1, 2, 3], null));
    }

    [Fact]
    public void SignVerify()
    {
        foreach (var p in Profiles)
        {
            var k = Vpqc.GenerateSigningKeypair(p);
            var sig = Vpqc.Sign(k.Secret, B("release"), B("app/v1"));
            Vpqc.Verify(k.Public, B("release"), B("app/v1"), sig);
            Assert.Throws<VerificationException>(() => Vpqc.Verify(k.Public, B("release"), B("app/v2"), sig));
            Assert.False(Vpqc.IsValid(k.Public, B("tampered"), B("app/v1"), sig));
            Assert.True(Vpqc.IsValid(k.Public, B("release"), B("app/v1"), sig));
        }
        var key = Vpqc.GenerateSigningKeypair();
        Assert.Throws<InvalidInputException>(() => Vpqc.Sign(key.Secret, B("m"), new byte[256]));
    }

    [Fact]
    public void KeyTextAndSecretKeyHygiene()
    {
        var k = Vpqc.GenerateEncryptionKeypair();
        var text = k.Public.ToText();
        Assert.StartsWith("-----BEGIN VPQC PUBLIC KEY-----", text);
        Assert.Equal(k.Public, PublicKey.FromText(text));
        using var sk = SecretKey.FromText(k.Secret.ToText());
        Assert.Equal(B("x"), Vpqc.Open(sk, Vpqc.Seal(k.Public, B("x")), null));
        Assert.Throws<InvalidInputException>(() => PublicKey.FromText(k.Secret.ToText()));
        Assert.Equal("SecretKey(<redacted>)", k.Secret.ToString());
        Assert.DoesNotContain("redacted", k.Public.ToText());
        var copy = SecretKey.FromBytes(k.Secret.ToBytes());
        copy.Dispose();
        Assert.Throws<ObjectDisposedException>(() => copy.ToBytes());
    }

    [Fact]
    public void ProtectedSecretKeys()
    {
        var k = Vpqc.GenerateEncryptionKeypair();
        var text = k.Secret.ToProtectedText("mật khẩu đủ dài", 8192);
        Assert.StartsWith("-----BEGIN VPQC PROTECTED SECRET KEY-----", text);
        Assert.True(SecretKey.IsProtected(B(text)));
        Assert.False(SecretKey.IsProtected(k.Secret.ToBytes()));
        using var back = SecretKey.FromProtected(text, "mật khẩu đủ dài");
        Assert.Equal(k.Secret.ToBytes(), back.ToBytes());
        Assert.Equal(B("p"), Vpqc.Open(back, Vpqc.Seal(k.Public, B("p")), null));
        Assert.Throws<DecryptionException>(() => SecretKey.FromProtected(text, "wrong"));
        Assert.Throws<InvalidInputException>(() => k.Secret.ToProtectedText("x", 1024));
        Assert.Throws<InvalidInputException>(() => k.Secret.ToProtectedText(""));
    }

    [Fact]
    public void FilesMultiRecipientAndRewrap()
    {
        var dir = Directory.CreateTempSubdirectory("vpqc-dotnet-").FullName;
        try
        {
            var data = new byte[300_000];
            new Random(7).NextBytes(data);
            File.WriteAllBytes(Path.Combine(dir, "in"), data);
            string P(string n) => Path.Combine(dir, n);

            var a = Vpqc.GenerateEncryptionKeypair();
            Assert.Equal((ulong)data.Length, Vpqc.EncryptFile(a.Public, P("in"), P("enc"), B("ctx")));
            Assert.Equal((ulong)data.Length, Vpqc.DecryptFile(a.Secret, P("enc"), P("out"), B("ctx")));
            Assert.Equal(data, File.ReadAllBytes(P("out")));
            Assert.Throws<DecryptionException>(() => Vpqc.DecryptFile(a.Secret, P("enc"), P("bad"), B("other")));
            Assert.False(File.Exists(P("bad")));
            Assert.Throws<VpqcIoException>(() => Vpqc.EncryptFile(a.Public, P("missing"), P("x")));

            var b = Vpqc.GenerateEncryptionKeypair(Profile.High);
            var c = Vpqc.GenerateEncryptionKeypair(Profile.Cnsa2);
            Vpqc.EncryptFileMulti([a.Public, b.Public], P("in"), P("menc"), B("team"));
            Vpqc.DecryptFile(b.Secret, P("menc"), P("mout"), B("team"));
            Assert.Equal(data, File.ReadAllBytes(P("mout")));
            Assert.Throws<DecryptionException>(() => Vpqc.DecryptFile(c.Secret, P("menc"), P("mx"), B("team")));
            Vpqc.RewrapFile(a.Secret, [b.Public, c.Public], P("menc"), P("mre"), B("team"));
            Vpqc.DecryptFile(c.Secret, P("mre"), P("mout2"), B("team"));
            Assert.Equal(data, File.ReadAllBytes(P("mout2")));
            Assert.Throws<DecryptionException>(() => Vpqc.DecryptFile(a.Secret, P("mre"), P("mx2"), B("team")));
            Assert.Throws<InvalidInputException>(() => Vpqc.EncryptFileMulti([], P("in"), P("none")));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void ConcurrentUse()
    {
        var k = Vpqc.GenerateEncryptionKeypair();
        System.Threading.Tasks.Parallel.For(0, 32, i =>
        {
            var msg = B($"message {i}");
            Assert.Equal(msg, Vpqc.Open(k.Secret, Vpqc.Seal(k.Public, msg), null));
        });
    }

    private static string? Cli() => Environment.GetEnvironmentVariable("VPQC_CLI");

    [Fact]
    public void InteroperatesWithTheCli()
    {
        var cli = Cli();
        if (string.IsNullOrEmpty(cli)) return; // set VPQC_CLI to run
        var dir = Directory.CreateTempSubdirectory("vpqc-dotnet-cli-").FullName;
        try
        {
            string Run(string args, string? passphrase = null)
            {
                var psi = new ProcessStartInfo(cli, args) { RedirectStandardOutput = true, RedirectStandardError = true, WorkingDirectory = dir };
                psi.Environment["VPQC_PASSPHRASE"] = passphrase ?? "";
                psi.Environment["VPQC_PASSPHRASE_FILE"] = "";
                using var p = Process.Start(psi)!;
                var o = p.StandardOutput.ReadToEnd();
                var e = p.StandardError.ReadToEnd();
                p.WaitForExit();
                Assert.True(p.ExitCode == 0, $"vpqc {args}: {e}");
                return o;
            }
            // CLI seals and signs, .NET opens and verifies.
            Run("keygen --purpose encrypt --out e --passphrase --kdf-memory 8", "shared passphrase 2026");
            using var sk = SecretKey.FromProtected(File.ReadAllText(Path.Combine(dir, "e.vpqc-secret")), "shared passphrase 2026");
            var pk = PublicKey.FromText(File.ReadAllText(Path.Combine(dir, "e.pub")));
            File.WriteAllText(Path.Combine(dir, "m.txt"), "from the cli");
            Run("seal --to e.pub --aad x -o m.sealed m.txt");
            Assert.Equal(B("from the cli"), Vpqc.Open(sk, File.ReadAllBytes(Path.Combine(dir, "m.sealed")), B("x")));
            // .NET seals, the CLI opens with a .NET-protected key.
            File.WriteAllBytes(Path.Combine(dir, "n.sealed"), Vpqc.Seal(pk, B("from dotnet"), B("y")));
            File.WriteAllText(Path.Combine(dir, "n.key"), sk.ToProtectedText("another passphrase 2026", 8192));
            Assert.Equal("from dotnet", Run("open --key n.key --aad y n.sealed", "another passphrase 2026"));
        }
        finally { Directory.Delete(dir, true); }
    }
}
