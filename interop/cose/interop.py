"""COSE/CWT interop: vpqc CLI <-> Python `cbor2` + OpenSSL ML-DSA (through `cryptography`).

An independent implementation of the COSE side: messages, Sig_structure and COSE_Keys are
built and parsed with cbor2, signatures made and checked by OpenSSL.
Usage: python interop.py VPQC_CLI WORKDIR   (python needs cryptography >= 50 and cbor2)
"""
import base64
import subprocess
import sys
import time

import cbor2
from cryptography.hazmat.primitives.asymmetric import mldsa

VPQC, W = sys.argv[1:3]
checks = failures = 0
ALGS = {"ML-DSA-65": (-49, mldsa.MLDSA65PrivateKey, mldsa.MLDSA65PublicKey),
        "ML-DSA-87": (-50, mldsa.MLDSA87PrivateKey, mldsa.MLDSA87PublicKey)}


def check(ok, what):
    global checks, failures
    checks += 1
    if not ok:
        failures += 1
        print("FAIL", what)


def vpqc(*args, stdin=b"", ok=True):
    r = subprocess.run([VPQC, *args], input=stdin, capture_output=True)
    if ok and r.returncode != 0:
        print("vpqc error:", r.stderr.decode().strip())
    return r.returncode == 0, r.stdout


def sig_structure(protected, aad, payload):
    return cbor2.dumps(["Signature1", protected, aad, payload])


def openssl_verify(pub, msg, aad=b"", payload=None):
    """Verify a vpqc COSE_Sign1 with OpenSSL; returns the payload or None."""
    item = cbor2.loads(msg)
    if isinstance(item, cbor2.CBORTag):
        if item.tag != 18:
            return None
        item = item.value
    protected, _unprotected, body, signature = item
    body = payload if body is None else body
    try:
        pub.verify(signature, sig_structure(protected, aad, body))
    except Exception:
        return None
    return body


def openssl_sign(priv, alg_id, payload, aad=b"", protected_extra=None, unprotected=None, tag=True):
    header = {1: alg_id}
    header.update(protected_extra or {})
    protected = cbor2.dumps(header, canonical=True) if header else b""
    sig = priv.sign(sig_structure(protected, aad, payload))
    msg = [protected, unprotected or {}, payload, sig]
    return cbor2.dumps(cbor2.CBORTag(18, msg) if tag else msg)


def write(name, data):
    path = f"{W}/{name}"
    open(path, "wb").write(data)
    return path


for name, (alg_id, Priv, Pub) in ALGS.items():
    p = f"{W}/{name}"
    # 1. vpqc keys read by Python.
    check(vpqc("cose", "key", "--alg", name, "--out", f"{p}.key", "--pub", f"{p}.pub")[0], f"{name} keygen")
    pub_map = cbor2.loads(open(f"{p}.pub", "rb").read())
    check(pub_map.keys() == {1, 3, -1} and pub_map[1] == 7 and pub_map[3] == alg_id,
          f"{name} public COSE_Key is {{kty: AKP, alg, pub}}")
    priv_map = cbor2.loads(open(f"{p}.key", "rb").read())
    check(len(priv_map[-2]) == 32, f"{name} priv is the 32-byte seed")
    pub = Pub.from_public_bytes(pub_map[-1])
    priv_from_seed = Priv.from_seed_bytes(priv_map[-2])
    check(priv_from_seed.public_key().public_bytes_raw() == pub_map[-1], f"{name} OpenSSL derives the same key from the seed")
    check(open(f"{p}.pub", "rb").read() == cbor2.dumps(pub_map, canonical=True), f"{name} COSE_Key is deterministic CBOR")

    # 2. vpqc signs, OpenSSL verifies.
    ok, msg = vpqc("cose", "sign", "--key", f"{p}.key", "--kid", "dev-1", "--content-type", "60", stdin=b"\xa1\x01\x02")
    check(ok and openssl_verify(pub, msg) == b"\xa1\x01\x02", f"{name} OpenSSL verifies vpqc COSE_Sign1")
    hdr = cbor2.loads(cbor2.loads(msg).value[0])
    check(hdr == {1: alg_id, 3: 60, 4: b"dev-1"}, f"{name} protected header alg/content type/kid")
    ok, msg = vpqc("cose", "sign", "--key", f"{p}.key", "--aad", "ctx", stdin=b"with aad")
    check(openssl_verify(pub, msg, b"ctx") == b"with aad", f"{name} OpenSSL verifies with external AAD")
    check(openssl_verify(pub, msg, b"other") is None, f"{name} OpenSSL rejects a wrong external AAD")
    ok, det = vpqc("cose", "sign", "--key", f"{p}.key", "--detached", stdin=b"firmware")
    check(cbor2.loads(det).value[2] is None and openssl_verify(pub, det, payload=b"firmware") == b"firmware",
          f"{name} detached payload")
    ok, text = vpqc("cose", "sign", "--key", f"{p}.key", "--base64", stdin=b"b64")
    raw = base64.urlsafe_b64decode(text.strip() + b"=" * (-len(text.strip()) % 4))
    check(openssl_verify(pub, raw) == b"b64", f"{name} base64url output")

    # 3. OpenSSL signs (cbor2 builds the message), vpqc verifies.
    okey = Priv.generate()
    opub_path = write(f"{name}-o.pub", cbor2.dumps({1: 7, 3: alg_id, -1: okey.public_key().public_bytes_raw()}, canonical=True))
    good = write(f"{name}-o.cose", openssl_sign(okey, alg_id, b"from OpenSSL", protected_extra={4: b"o"}))
    ok, out = vpqc("cose", "verify", "--key", opub_path, good)
    check(ok and out == b"from OpenSSL", f"{name} vpqc verifies OpenSSL COSE_Sign1")
    untagged = write(f"{name}-u.cose", openssl_sign(okey, alg_id, b"untagged", tag=False))
    check(vpqc("cose", "verify", "--key", opub_path, untagged)[1] == b"untagged", f"{name} untagged accepted")
    aad = write(f"{name}-a.cose", openssl_sign(okey, alg_id, b"x", aad=b"ctx"))
    check(vpqc("cose", "verify", "--key", opub_path, "--aad", "ctx", aad)[0], f"{name} vpqc: AAD accepted")
    check(not vpqc("cose", "verify", "--key", opub_path, aad, ok=False)[0], f"{name} vpqc: missing AAD rejected")
    bad = {
        "tampered payload": cbor2.dumps(cbor2.CBORTag(18, (lambda m: [m[0], m[1], b"From OpenSSL", m[3]])(
            cbor2.loads(open(good, "rb").read()).value))),
        "alg unprotected": (lambda: (lambda sig_p: cbor2.dumps(cbor2.CBORTag(18, [b"", {1: alg_id}, b"x", sig_p])))(
            okey.sign(sig_structure(b"", b"", b"x"))))(),
        "crit": openssl_sign(okey, alg_id, b"x", protected_extra={2: [4], 4: b"k"}),
        "kid in both buckets": openssl_sign(okey, alg_id, b"x", protected_extra={4: b"a"}, unprotected={4: b"b"}),
        "other alg id": openssl_sign(okey, -7, b"x"),
        "wrong ML-DSA level": openssl_sign(okey, -50 if alg_id == -49 else -49, b"x"),
        "wrong tag": cbor2.dumps(cbor2.CBORTag(98, cbor2.loads(open(good, "rb").read()).value)),
        "other key": openssl_sign(Priv.generate(), alg_id, b"x"),
        "indefinite-length array": b"\xd2\x9f" + b"".join(cbor2.dumps(x) for x in cbor2.loads(open(good, "rb").read()).value) + b"\xff",
    }
    for what, m in bad.items():
        path = write(f"{name}-bad.cose", m)
        check(not vpqc("cose", "verify", "--key", opub_path, path, ok=False)[0], f"{name} vpqc rejects: {what}")

    # A private COSE_Key made by Python is usable by vpqc.
    seed_key = Priv.generate()
    kpath = write(f"{name}-o.key", cbor2.dumps({1: 7, 3: alg_id, -1: seed_key.public_key().public_bytes_raw(),
                                                -2: seed_key.private_bytes_raw()}, canonical=True))
    ok, msg = vpqc("cose", "sign", "--key", kpath, stdin=b"python key")
    check(ok and openssl_verify(seed_key.public_key(), msg) == b"python key", f"{name} vpqc signs with an OpenSSL-made key")

    # 4. CWT both ways.
    ok, tok = vpqc("cwt", "sign", "--key", f"{p}.key", "--iss", "as", "--sub", "s1", "--aud", "rs", "--ttl", "300")
    claims = cbor2.loads(openssl_verify(pub, tok) or b"\xa0")
    check(claims.get(1) == "as" and claims.get(2) == "s1" and claims.get(3) == "rs" and claims[4] - claims[6] == 300,
          f"{name} OpenSSL verifies a vpqc CWT, claims as expected")
    now = int(time.time())
    cwt = openssl_sign(okey, alg_id, cbor2.dumps({1: "as", 3: ["rs", "other"], 4: now + 100.5, 6: now}))
    tagged = write(f"{name}-o.cwt", cbor2.dumps(cbor2.CBORTag(61, cbor2.loads(cwt))))
    ok, out = vpqc("cwt", "verify", "--key", opub_path, "--aud", "rs", "--iss", "as", tagged)
    check(ok and b'"iss":"as"' in out, f"{name} vpqc verifies an OpenSSL CWT (tag 61, aud array, float exp)")
    check(not vpqc("cwt", "verify", "--key", opub_path, "--aud", "zz", tagged, ok=False)[0], f"{name} CWT wrong audience rejected")
    expired = write(f"{name}-x.cwt", openssl_sign(okey, alg_id, cbor2.dumps({4: now - 3600})))
    check(not vpqc("cwt", "verify", "--key", opub_path, expired, ok=False)[0], f"{name} expired CWT rejected")
    no_exp = write(f"{name}-n.cwt", openssl_sign(okey, alg_id, cbor2.dumps({2: "s"})))
    check(not vpqc("cwt", "verify", "--key", opub_path, no_exp, ok=False)[0], f"{name} CWT without exp rejected")

print(f"cose interop: {checks - failures} passed, {failures} failed")
sys.exit(1 if failures else 0)
