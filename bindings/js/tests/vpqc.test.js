const test = require("node:test");
const assert = require("node:assert/strict");
const vpqc = require("../pkg/node/vpqc.js");

const enc = new TextEncoder();
const dec = new TextDecoder();

function throwsCode(fn, code) {
  assert.throws(fn, (e) => e instanceof Error && e.name === "VpqcError" && e.code === code, `expected ${code}`);
}

test("encrypt round trip, all profiles", () => {
  for (const profile of ["standard", "fast-auth", "cnsa2", undefined]) {
    const keys = vpqc.generateEncryptionKeypair(profile);
    const sealed = vpqc.seal(keys.publicKey, enc.encode("secret"), enc.encode("ctx"));
    assert.equal(dec.decode(vpqc.unseal(keys.secretKey, sealed, enc.encode("ctx"))), "secret");
  }
});

test("wrong aad / wrong key / tampering", () => {
  const a = vpqc.generateEncryptionKeypair();
  const b = vpqc.generateEncryptionKeypair();
  const sealed = vpqc.seal(a.publicKey, enc.encode("secret"), enc.encode("one"));
  throwsCode(() => vpqc.unseal(a.secretKey, sealed, enc.encode("two")), "DECRYPTION_FAILED");
  throwsCode(() => vpqc.unseal(b.secretKey, sealed, enc.encode("one")), "DECRYPTION_FAILED");
  for (const i of [0, 6, 12, 500, sealed.length - 1]) {
    const bad = sealed.slice();
    bad[i] ^= 1;
    assert.throws(() => vpqc.unseal(a.secretKey, bad, enc.encode("one")), /./);
  }
});

test("sign / verify", () => {
  for (const profile of ["standard", "fast-auth", "cnsa2"]) {
    const keys = vpqc.generateSigningKeypair(profile);
    const sig = vpqc.sign(keys.secretKey, enc.encode("msg"), enc.encode("app/v1"));
    vpqc.verify(keys.publicKey, enc.encode("msg"), enc.encode("app/v1"), sig);
    throwsCode(() => vpqc.verify(keys.publicKey, enc.encode("msg"), enc.encode("app/v2"), sig), "VERIFICATION_FAILED");
    throwsCode(() => vpqc.verify(keys.publicKey, enc.encode("other"), enc.encode("app/v1"), sig), "VERIFICATION_FAILED");
  }
});

test("input validation", () => {
  throwsCode(() => vpqc.generateEncryptionKeypair("nope"), "INVALID_INPUT");
  const s = vpqc.generateSigningKeypair();
  throwsCode(() => vpqc.sign(s.secretKey, enc.encode("m"), new Uint8Array(256)), "INVALID_INPUT");
  throwsCode(() => vpqc.seal(s.publicKey, enc.encode("m"), new Uint8Array()), "INVALID_INPUT"); // signing key cannot encrypt
  throwsCode(() => vpqc.seal(new Uint8Array([1, 2, 3]), enc.encode("m"), new Uint8Array()), "INVALID_INPUT");
});

test("armored public key", () => {
  const keys = vpqc.generateEncryptionKeypair();
  const text = vpqc.publicKeyToText(keys.publicKey);
  assert.match(text, /^-----BEGIN VPQC PUBLIC KEY-----/);
  assert.deepEqual(vpqc.publicKeyFromText(text), keys.publicKey);
});

test("large message", () => {
  const keys = vpqc.generateEncryptionKeypair();
  const data = new Uint8Array(1 << 20).map((_, i) => i & 0xff);
  const out = vpqc.unseal(keys.secretKey, vpqc.seal(keys.publicKey, data, new Uint8Array()), new Uint8Array());
  assert.deepEqual(out, data);
});

test("interop: Node output opened by the Rust CLI", { skip: !process.env.VPQC_CLI }, () => {
  const { execFileSync } = require("node:child_process");
  const fs = require("node:fs");
  const os = require("node:os");
  const path = require("node:path");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vpqc-"));
  const cli = process.env.VPQC_CLI;
  execFileSync(cli, ["keygen", "--purpose", "encrypt", "--out", path.join(dir, "k")]);
  const pub = vpqc.publicKeyFromText(fs.readFileSync(path.join(dir, "k.pub"), "utf8"));
  const sealed = vpqc.seal(pub, enc.encode("from node"), enc.encode("x"));
  fs.writeFileSync(path.join(dir, "m.sealed"), sealed);
  const out = execFileSync(cli, ["open", "--key", path.join(dir, "k.vpqc-secret"), "--aad", "x", path.join(dir, "m.sealed")]);
  assert.equal(out.toString(), "from node");
});
