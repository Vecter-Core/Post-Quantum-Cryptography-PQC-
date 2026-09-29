"""X.509 interop: vpqc CLI <-> OpenSSL (Python `cryptography`) and Node.js (OpenSSL 3.5).

Usage: python interop.py VPQC_CLI NODE WORKDIR   (python must have cryptography with ML-DSA)
"""
import base64
import datetime
import subprocess
import sys

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import mldsa
from cryptography.x509 import verification
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

VPQC, NODE, W = sys.argv[1:4]
checks = failures = 0


def check(ok, what):
    global checks, failures
    checks += 1
    if not ok:
        failures += 1
        print("FAIL", what)


def vpqc(*args, ok=True):
    r = subprocess.run([VPQC, *args], capture_output=True, text=True)
    if ok and r.returncode != 0:
        print("vpqc error:", r.stderr.strip())
    return r.returncode == 0, r.stdout


def node(script, *args):
    r = subprocess.run([NODE, "--no-warnings", "-e", script, *args], capture_output=True, text=True)
    return r.returncode == 0, (r.stdout + r.stderr).strip()


def load(path):
    return x509.load_pem_x509_certificate(open(path, "rb").read())


def server_verifier(roots, name):
    return verification.PolicyBuilder().store(verification.Store(roots)).build_server_verifier(x509.DNSName(name))


NODE_CHAIN = """
const {X509Certificate} = require('crypto'); const fs = require('fs');
const certs = process.argv.slice(1).map(f => new X509Certificate(fs.readFileSync(f)));
for (let i = 0; i + 1 < certs.length; i++) {
  if (!certs[i].checkIssued(certs[i + 1])) throw new Error('checkIssued ' + i);
  if (!certs[i].verify(certs[i + 1].publicKey)) throw new Error('verify ' + i);
}
const root = certs[certs.length - 1];
if (!root.verify(root.publicKey)) throw new Error('root self-signature');
console.log(certs.map(c => c.publicKey.asymmetricKeyType).join(','));
"""

# 1. vpqc builds root (ML-DSA-87) -> intermediate (ML-DSA-65) -> server leaf; OpenSSL checks.
for alg in ("ML-DSA-65", "ML-DSA-87"):
    p = f"{W}/v-{alg}"
    vpqc("x509", "key", "--alg", "ML-DSA-87", "--out", f"{p}-root.key", "--force")
    vpqc("x509", "key", "--alg", alg, "--out", f"{p}-int.key", "--force")
    vpqc("x509", "key", "--alg", alg, "--out", f"{p}-leaf.key", "--force")
    subprocess.run(["rm", "-f", f"{p}-root.pem", f"{p}-int.pem", f"{p}-leaf.pem"])
    check(vpqc("x509", "ca", "--key", f"{p}-root.key", "--cn", "vpqc Root", "--path-len", "1", "-o", f"{p}-root.pem")[0], "vpqc root")
    check(vpqc("x509", "issue", "--ca", f"{p}-root.pem", "--ca-key", f"{p}-root.key", "--subject-key", f"{p}-int.key",
               "--cn", "vpqc Intermediate", "--intermediate-ca", "--days", "365", "-o", f"{p}-int.pem")[0], "vpqc intermediate")
    check(vpqc("x509", "issue", "--ca", f"{p}-int.pem", "--ca-key", f"{p}-int.key", "--subject-key", f"{p}-leaf.key",
               "--cn", "svc.example.org", "--dns", "svc.example.org", "--purpose", "server", "-o", f"{p}-leaf.pem")[0], "vpqc leaf")
    root, inter, leaf = load(f"{p}-root.pem"), load(f"{p}-int.pem"), load(f"{p}-leaf.pem")
    for child, parent, what in ((root, root, "root"), (inter, root, "intermediate"), (leaf, inter, "leaf")):
        try:
            child.verify_directly_issued_by(parent)
            check(True, "")
        except Exception as e:
            check(False, f"{alg} OpenSSL signature check of vpqc {what}: {e}")
    try:
        path = server_verifier([root], "svc.example.org").verify(leaf, [inter])
        check(len(path) == 3, f"{alg} path length")
    except Exception as e:
        check(False, f"{alg} cryptography PolicyBuilder rejected vpqc chain: {e}")
    try:
        server_verifier([root], "other.example.org").verify(leaf, [inter])
        check(False, f"{alg} cryptography accepted wrong name")
    except verification.VerificationError:
        check(True, "")
    ok, out = node(NODE_CHAIN, f"{p}-leaf.pem", f"{p}-int.pem", f"{p}-root.pem")
    check(ok and out == f"{alg.lower()},{alg.lower()},ml-dsa-87", f"{alg} Node chain check: {out}")
    for part in ("root", "int", "leaf"):
        k = serialization.load_pem_private_key(open(f"{p}-{part}.key", "rb").read(), None)
        cert = {"root": root, "int": inter, "leaf": leaf}[part]
        check(k.public_key() == cert.public_key(), f"{alg} OpenSSL imports vpqc {part} key")

# 2. OpenSSL builds a chain; vpqc verifies it (and rejects bad variants).
now = datetime.datetime.now(datetime.timezone.utc)


def build(subject, issuer, pub, key, ca, days=30, start=None, dns=None, eku=None, path_len=None):
    start = start or now - datetime.timedelta(minutes=1)
    b = (x509.CertificateBuilder()
         .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
         .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)]))
         .public_key(pub).serial_number(x509.random_serial_number())
         .not_valid_before(start).not_valid_after(start + datetime.timedelta(days=days))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=path_len), critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(pub), critical=False))
    if ca:
        b = b.add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
    else:
        b = b.add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
    if dns:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in dns]), critical=False)
    if eku:
        b = b.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    return b.sign(key, None)


def write(path, cert):
    open(path, "wb").write(cert.public_bytes(serialization.Encoding.PEM))


for alg, gen in (("ML-DSA-65", mldsa.MLDSA65PrivateKey), ("ML-DSA-87", mldsa.MLDSA87PrivateKey)):
    p = f"{W}/o-{alg}"
    root_k, leaf_k = gen.generate(), gen.generate()
    root = build("OpenSSL Root", "OpenSSL Root", root_k.public_key(), root_k, True, days=365)
    leaf = build("web.example.net", "OpenSSL Root", leaf_k.public_key(), root_k, False,
                 dns=["web.example.net", "*.cdn.example.net"], eku=[ExtendedKeyUsageOID.SERVER_AUTH])
    write(f"{p}-root.pem", root)
    write(f"{p}-leaf.pem", leaf)
    ok, out = vpqc("x509", "verify", "--ca", f"{p}-root.pem", "--dns", "a.cdn.example.net", "--purpose", "server", f"{p}-leaf.pem")
    check(ok and out.strip().endswith("OK"), f"{alg} vpqc verifies OpenSSL chain")
    check(not vpqc("x509", "verify", "--ca", f"{p}-root.pem", "--dns", "a.b.cdn.example.net", f"{p}-leaf.pem", ok=False)[0],
          f"{alg} vpqc: wildcard must match one label only")
    check(not vpqc("x509", "verify", "--ca", f"{p}-root.pem", "--purpose", "client", f"{p}-leaf.pem", ok=False)[0],
          f"{alg} vpqc: wrong purpose rejected")
    expired = build("old.example.net", "OpenSSL Root", leaf_k.public_key(), root_k, False, days=1,
                    start=now - datetime.timedelta(days=10), dns=["old.example.net"])
    write(f"{p}-expired.pem", expired)
    check(not vpqc("x509", "verify", "--ca", f"{p}-root.pem", f"{p}-expired.pem", ok=False)[0], f"{alg} vpqc: expired rejected")
    other_k = gen.generate()
    forged = build("web.example.net", "OpenSSL Root", leaf_k.public_key(), other_k, False, dns=["web.example.net"])
    write(f"{p}-forged.pem", forged)
    check(not vpqc("x509", "verify", "--ca", f"{p}-root.pem", f"{p}-forged.pem", ok=False)[0], f"{alg} vpqc: wrong signer rejected")
    no_ca = build("fake CA", "OpenSSL Root", other_k.public_key(), root_k, False)
    sub = build("sub.example.net", "fake CA", leaf_k.public_key(), other_k, False, dns=["sub.example.net"])
    write(f"{p}-noca.pem", no_ca)
    write(f"{p}-sub.pem", sub)
    check(not vpqc("x509", "verify", "--ca", f"{p}-root.pem", "--chain", f"{p}-noca.pem", f"{p}-sub.pem", ok=False)[0],
          f"{alg} vpqc: non-CA issuer rejected")
    pl0 = build("PL0 CA", "OpenSSL Root", other_k.public_key(), root_k, True, path_len=0)
    third_k = gen.generate()
    pl_int = build("Deeper CA", "PL0 CA", third_k.public_key(), other_k, True)
    deep = build("deep.example.net", "Deeper CA", leaf_k.public_key(), third_k, False, dns=["deep.example.net"])
    for n, c in (("pl0", pl0), ("plint", pl_int), ("deep", deep)):
        write(f"{p}-{n}.pem", c)
    check(not vpqc("x509", "verify", "--ca", f"{p}-root.pem", "--chain", f"{p}-pl0.pem", "--chain", f"{p}-plint.pem",
                   f"{p}-deep.pem", ok=False)[0], f"{alg} vpqc: path length constraint enforced")
    der = bytearray(leaf.public_bytes(serialization.Encoding.DER))
    der[200] ^= 1
    open(f"{p}-tampered.pem", "wb").write(
        b"-----BEGIN CERTIFICATE-----\n" + base64.encodebytes(bytes(der)) + b"-----END CERTIFICATE-----\n")
    check(not vpqc("x509", "verify", "--ca", f"{p}-root.pem", f"{p}-tampered.pem", ok=False)[0], f"{alg} vpqc: tampered rejected")

    # OpenSSL-generated PKCS#8 (seed form) used by vpqc as the subject key and as a CA key.
    kp = f"{p}-openssl.key"
    open(kp, "wb").write(leaf_k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                              serialization.NoEncryption()))
    subprocess.run(["rm", "-f", f"{p}-from-openssl-key.pem"])
    open(f"{p}-root.key", "wb").write(root_k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                             serialization.NoEncryption()))
    check(vpqc("x509", "issue", "--ca", f"{p}-root.pem", "--ca-key", f"{p}-root.key", "--subject-key", kp,
               "--cn", "k.example.net", "--dns", "k.example.net", "-o", f"{p}-from-openssl-key.pem")[0], f"{alg} vpqc issues with OpenSSL keys")
    cert = load(f"{p}-from-openssl-key.pem")
    check(cert.public_key() == leaf_k.public_key(), f"{alg} subject key preserved")
    try:
        server_verifier([root], "k.example.net").verify(cert, [])
        check(True, "")
    except Exception as e:
        check(False, f"{alg} cryptography rejects cert vpqc issued under an OpenSSL root: {e}")

# 3. Node-generated PKCS#8 (RFC 9881 'both' form: seed + expanded key) imported by vpqc; a
#    modified expanded key must be rejected.
for alg in ("ml-dsa-65", "ml-dsa-87"):
    ok, out = node("const c=require('crypto');const {privateKey}=c.generateKeyPairSync(process.argv[1]);"
                   "process.stdout.write(privateKey.export({type:'pkcs8',format:'der'}).toString('base64'))", alg)
    check(ok, f"{alg} node keygen")
    der = base64.b64decode(out)
    def pem(d):
        return "-----BEGIN PRIVATE KEY-----\n" + base64.encodebytes(d).decode() + "-----END PRIVATE KEY-----\n"
    good, bad = f"{W}/node-{alg}.key", f"{W}/node-{alg}-bad.key"
    open(good, "w").write(pem(der))
    mod = bytearray(der)
    mod[-10] ^= 1
    open(bad, "w").write(pem(bytes(mod)))
    root = f"{W}/o-ML-DSA-65-root"
    subprocess.run(["rm", "-f", f"{W}/node-{alg}.pem", f"{W}/node-{alg}-bad.pem"])
    check(vpqc("x509", "issue", "--ca", f"{root}.pem", "--ca-key", f"{root}.key", "--subject-key", good,
               "--cn", "n.example.net", "-o", f"{W}/node-{alg}.pem")[0], f"{alg} vpqc imports Node PKCS#8 (both form)")
    check(not vpqc("x509", "issue", "--ca", f"{root}.pem", "--ca-key", f"{root}.key", "--subject-key", bad,
                   "--cn", "n.example.net", "-o", f"{W}/node-{alg}-bad.pem", ok=False)[0], f"{alg} vpqc rejects inconsistent both form")

print(f"x509 interop: {checks} checks, {failures} failures")
sys.exit(1 if failures else 0)
