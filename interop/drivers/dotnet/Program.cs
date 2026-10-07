// .NET driver for the interoperability suite. See interop/run.sh.
using System;
using System.IO;
using System.Linq;
using System.Text;
using Vecter.Vpqc;

static byte[] U(string s) => Encoding.UTF8.GetBytes(s);
static PublicKey Pub(string path) => PublicKey.FromText(File.ReadAllText(path));
static SecretKey Sec(string path) => SecretKey.FromText(File.ReadAllText(path));
static Profile Prof(string name) => name switch
{
    "standard" => Profile.Standard,
    "fast-auth" => Profile.FastAuth,
    "cnsa2" => Profile.Cnsa2,
    "high" => Profile.High,
    _ => throw new ArgumentException($"unknown profile {name}"),
};

try
{
    var a = args.Skip(1).ToArray();
    switch (args[0])
    {
        case "keygen": // keygen encrypt|sign PROFILE OUT_PREFIX
        {
            var kp = a[0] == "encrypt" ? Vpqc.GenerateEncryptionKeypair(Prof(a[1])) : Vpqc.GenerateSigningKeypair(Prof(a[1]));
            File.WriteAllText(a[2] + ".pub", kp.Public.ToText());
            File.WriteAllText(a[2] + ".sec", kp.Secret.ToText());
            break;
        }
        case "seal": // seal PUBFILE AAD IN OUT
            File.WriteAllBytes(a[3], Vpqc.Seal(Pub(a[0]), File.ReadAllBytes(a[2]), U(a[1])));
            break;
        case "open": // open SECFILE AAD IN OUT
            File.WriteAllBytes(a[3], Vpqc.Open(Sec(a[0]), File.ReadAllBytes(a[2]), U(a[1])));
            break;
        case "sign": // sign SECFILE CTX IN OUT
            File.WriteAllBytes(a[3], Vpqc.Sign(Sec(a[0]), File.ReadAllBytes(a[2]), U(a[1])));
            break;
        case "verify": // verify PUBFILE CTX SIG IN
            Vpqc.Verify(Pub(a[0]), File.ReadAllBytes(a[3]), U(a[1]), File.ReadAllBytes(a[2]));
            break;
        case "encrypt-file": // encrypt-file PUBFILE AAD IN OUT
            Vpqc.EncryptFile(Pub(a[0]), a[2], a[3], U(a[1]));
            break;
        case "encrypt-file-multi": // encrypt-file-multi AAD IN OUT PUBFILE...
            Vpqc.EncryptFileMulti(a.Skip(3).Select(Pub), a[1], a[2], U(a[0]));
            break;
        case "rewrap-file": // rewrap-file SECFILE AAD IN OUT PUBFILE...
            Vpqc.RewrapFile(Sec(a[0]), a.Skip(4).Select(Pub), a[2], a[3], U(a[1]));
            break;
        case "decrypt-file": // decrypt-file SECFILE AAD IN OUT
            Vpqc.DecryptFile(Sec(a[0]), a[2], a[3], U(a[1]));
            break;
        case "protect": // protect SECFILE PASSPHRASE OUT
            File.WriteAllText(a[2], Sec(a[0]).ToProtectedText(a[1], 8192));
            break;
        case "unprotect": // unprotect PROTFILE PASSPHRASE OUT
            File.WriteAllText(a[2], SecretKey.FromProtected(File.ReadAllText(a[0]), a[1]).ToText());
            break;
        default:
            throw new ArgumentException($"unknown command {args[0]}");
    }
}
catch (Exception e) when (e is VpqcException or ArgumentException or IOException)
{
    Console.Error.WriteLine($"dotnet-driver: {e.Message}");
    Environment.Exit(1);
}
