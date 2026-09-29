const test = require("node:test");
const assert = require("node:assert/strict");
const vpqc = require("../pkg/node/vpqc.js");

const enc = new TextEncoder();
const dec = new TextDecoder();

function throwsCode(fn, code) {
  assert.throws(fn, (e) => e instanceof Error && e.name === "VpqcError" && e.code === code, `expected ${code}`);
}

test("encrypt round trip, all profiles", () => {
  for (const profile of ["standard", "fast-auth", "cnsa2", "high", undefined]) {
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
  for (const profile of ["standard", "fast-auth", "cnsa2", "high"]) {
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

test("incremental stream encryption", () => {
  const keys = vpqc.generateEncryptionKeypair();
  const data = new Uint8Array(500_000).map((_, i) => (i * 13) & 0xff);
  const enc = new vpqc.StreamEncryptor(keys.publicKey, enc8("ctx"));
  const parts = [];
  for (let i = 0; i < data.length; i += 20_000) parts.push(enc.push(data.subarray(i, i + 20_000)));
  parts.push(enc.finish());
  const ct = concat(parts);
  const dec = new vpqc.StreamDecryptor(keys.secretKey, enc8("ctx"));
  const out = [];
  for (let i = 0; i < ct.length; i += 7_777) out.push(dec.push(ct.subarray(i, i + 7_777)));
  out.push(dec.finish());
  assert.deepEqual(concat(out), data);

  const cut = new vpqc.StreamDecryptor(keys.secretKey, enc8("ctx"));
  cut.push(ct.subarray(0, ct.length - 5));
  throwsCode(() => cut.finish(), "DECRYPTION_FAILED");
  const wrong = new vpqc.StreamDecryptor(keys.secretKey, enc8("other"));
  throwsCode(() => { wrong.push(ct); wrong.finish(); }, "DECRYPTION_FAILED");
});

test("several recipients and rewrap", () => {
  const a = vpqc.generateEncryptionKeypair();
  const b = vpqc.generateEncryptionKeypair("high");
  const c = vpqc.generateEncryptionKeypair("cnsa2");
  const data = new Uint8Array(100_000).map((_, i) => (i * 7) & 0xff);
  const e = new vpqc.StreamEncryptor([a.publicKey, b.publicKey], enc8("t"));
  const ct = concat([e.push(data), e.finish()]);
  const open = (k, bytes) => {
    const d = new vpqc.StreamDecryptor(k.secretKey, enc8("t"));
    return concat([d.push(bytes), d.finish()]);
  };
  assert.deepEqual(open(a, ct), data);
  assert.deepEqual(open(b, ct), data);
  throwsCode(() => open(c, ct), "DECRYPTION_FAILED");

  const re = vpqc.rewrap(b.secretKey, [b.publicKey, c.publicKey], enc8("t"), ct);
  assert.deepEqual(open(c, re), data);
  throwsCode(() => open(a, re), "DECRYPTION_FAILED");
  throwsCode(() => vpqc.rewrap(a.secretKey, [a.publicKey], enc8("t"), re), "DECRYPTION_FAILED");
  assert.throws(() => new vpqc.StreamEncryptor("not a key", enc8("t")), TypeError);
});

function enc8(s) {
  return new TextEncoder().encode(s);
}

function concat(parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}
