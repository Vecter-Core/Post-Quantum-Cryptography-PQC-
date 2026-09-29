"""Protected secret key interop (ADR-0013): the passphrase format checked with independent
implementations, argon2-cffi (the Argon2 reference C code) and PyNaCl (libsodium
XChaCha20-Poly1305).

Python decrypts keys protected by vpqc and gets exactly vpqc's plain key; Python protects a
vpqc key the same way and vpqc uses it.
Usage: python interop.py VPQC_CLI WORKDIR   (python needs argon2-cffi and pynacl)
"""
import base64
import os
import struct
import subprocess
import sys

import argon2.low_level as argon2
import nacl.bindings as sodium

VPQC, W = sys.argv[1:3]
PASS = "mật khẩu đủ dài 2026"
checks = failures = 0


def check(ok, what):
    global checks, failures
    checks += 1
    if not ok:
        failures += 1
        print("FAIL", what)


def vpqc(*args, ok=True, passphrase=PASS):
    env = dict(os.environ, VPQC_PASSPHRASE=passphrase)
    env.pop("VPQC_PASSPHRASE_FILE", None)
    r = subprocess.run([VPQC, *args], capture_output=True, env=env, cwd=W)
    if ok and r.returncode != 0:
        print("vpqc error:", r.stderr.decode().strip())
    return r.returncode == 0, r.stdout


def dearmor(text, label):
    lines = text.strip().splitlines()
    assert lines[0] == f"-----BEGIN {label}-----" and lines[-1] == f"-----END {label}-----", lines[0]
    return base64.b64decode("".join(lines[1:-1]))


def armor(data, label):
    b64 = base64.b64encode(data).decode()
    body = "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
    return f"-----BEGIN {label}-----\n{body}\n-----END {label}-----\n"


def parse(blob):
    """Return (header, nonce, ciphertext, m, t, p, salt) of a passphrase-protected key."""
    assert blob[:4] == b"VPQC" and blob[4] == 1 and blob[5] == 7 and blob[6] == 1
    (plen,) = struct.unpack(">H", blob[7:9])
    m, t, p = struct.unpack(">III", blob[9:21])
    salt = blob[21:37]
    assert plen == 28
    nonce = blob[37:61]
    return blob[:61], nonce, blob[61:], m, t, p, salt


def kek(m, t, p, salt, passphrase=PASS):
    return argon2.hash_secret_raw(passphrase.encode(), salt, time_cost=t, memory_cost=m,
                                  parallelism=p, hash_len=32, type=argon2.Type.ID, version=19)


for purpose, profile in (("encrypt", "standard"), ("sign", "standard"), ("encrypt", "cnsa2"), ("sign", "high")):
    name = f"{purpose}-{profile}"
    ok, _ = vpqc("keygen", "--purpose", purpose, "--profile", profile, "--out", name, "--passphrase",
                 "--kdf-memory", "32")
    check(ok, f"{name}: keygen --passphrase")
    ok, _ = vpqc("unprotect", f"{name}.vpqc-secret", "-o", f"{name}.plain")
    plain = dearmor(open(f"{W}/{name}.plain").read(), "VPQC SECRET KEY")
    blob = dearmor(open(f"{W}/{name}.vpqc-secret").read(), "VPQC PROTECTED SECRET KEY")
    header, nonce, ct, m, t, p, salt = parse(blob)
    check((m, t, p) == (32 * 1024, 3, 4), f"{name}: Argon2id parameters recorded")
    # 1. Independent decryption: argon2-cffi + libsodium, header as associated data.
    inner = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(ct, header, nonce, kek(m, t, p, salt))
    check(inner == plain, f"{name}: argon2-cffi + libsodium decrypt vpqc's protected key")
    try:
        sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(ct, header[:-1] + bytes([header[-1] ^ 1]), nonce,
                                                         kek(m, t, p, salt))
        check(False, f"{name}: header is authenticated")
    except Exception:
        check(True, f"{name}: header is authenticated")

    # 2. Python protects the plain key; vpqc must accept it (and reject a wrong passphrase).
    salt2, nonce2 = os.urandom(16), os.urandom(24)
    m2, t2, p2 = 8 * 1024, 2, 1
    hdr2 = b"VPQC\x01\x07\x01" + struct.pack(">H", 28) + struct.pack(">III", m2, t2, p2) + salt2 + nonce2
    ct2 = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plain, hdr2, nonce2, kek(m2, t2, p2, salt2))
    open(f"{W}/{name}.py", "w").write(armor(hdr2 + ct2, "VPQC PROTECTED SECRET KEY"))
    ok, _ = vpqc("unprotect", f"{name}.py", "-o", f"{name}.py.plain")
    check(ok and dearmor(open(f"{W}/{name}.py.plain").read(), "VPQC SECRET KEY") == plain,
          f"{name}: vpqc opens a key protected by argon2-cffi + libsodium")
    check(not vpqc("unprotect", f"{name}.py", "-o", f"{name}.x", ok=False, passphrase="wrong")[0],
          f"{name}: wrong passphrase rejected")
    # A Python-written key with cost parameters outside vpqc's bounds is refused before any work.
    hdr3 = b"VPQC\x01\x07\x01" + struct.pack(">H", 28) + struct.pack(">III", 4 << 20, 1, 1) + salt2 + nonce2
    open(f"{W}/{name}.huge", "w").write(armor(hdr3 + ct2, "VPQC PROTECTED SECRET KEY"))
    check(not vpqc("unprotect", f"{name}.huge", "-o", f"{name}.y", ok=False)[0],
          f"{name}: 4 GiB Argon2 memory refused")

print(f"key protection interop: {checks - failures} passed, {failures} failed")
sys.exit(1 if failures else 0)
