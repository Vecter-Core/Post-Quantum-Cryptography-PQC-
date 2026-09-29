// Node.js driver for the interoperability suite. See interop/run.sh.
const fs = require("node:fs");
const path = require("node:path");
const vpqc = require(path.join(__dirname, "../../bindings/js/pkg/node/vpqc.js"));

const [cmd, ...a] = process.argv.slice(2);
const read = (p) => new Uint8Array(fs.readFileSync(p));
const enc = (s) => new TextEncoder().encode(s);
const pub = (p) => vpqc.publicKeyFromText(fs.readFileSync(p, "utf8"));
const sec = (p) => vpqc.secretKeyFromText(fs.readFileSync(p, "utf8"));

// Stream a file through a StreamEncryptor/StreamDecryptor in 256 KiB pieces into a temporary
// file that is renamed only after finish() succeeds.
function pipeFile(stream, input, output) {
  const tmp = `${output}.${process.pid}.tmp`;
  const fin = fs.openSync(input, "r");
  const fout = fs.openSync(tmp, "wx", 0o600);
  try {
    const buf = Buffer.alloc(1 << 18);
    let n;
    while ((n = fs.readSync(fin, buf, 0, buf.length, null)) > 0) fs.writeSync(fout, stream.push(buf.subarray(0, n)));
    fs.writeSync(fout, stream.finish());
    fs.fsyncSync(fout);
    fs.closeSync(fout);
    fs.renameSync(tmp, output);
  } catch (e) {
    try { fs.closeSync(fout); } catch {}
    fs.rmSync(tmp, { force: true });
    throw e;
  } finally {
    fs.closeSync(fin);
  }
}

try {
  switch (cmd) {
    case "keygen": { // keygen encrypt|sign PROFILE_NAME OUT_PREFIX
      const kp = a[0] === "encrypt" ? vpqc.generateEncryptionKeypair(a[1]) : vpqc.generateSigningKeypair(a[1]);
      fs.writeFileSync(a[2] + ".pub", vpqc.publicKeyToText(kp.publicKey));
      fs.writeFileSync(a[2] + ".sec", vpqc.secretKeyToText(kp.secretKey));
      break;
    }
    case "seal": fs.writeFileSync(a[3], vpqc.seal(pub(a[0]), read(a[2]), enc(a[1]))); break;
    case "open": fs.writeFileSync(a[3], vpqc.unseal(sec(a[0]), read(a[2]), enc(a[1]))); break;
    case "sign": fs.writeFileSync(a[3], vpqc.sign(sec(a[0]), read(a[2]), enc(a[1]))); break;
    case "verify": vpqc.verify(pub(a[0]), read(a[3]), enc(a[1]), read(a[2])); break;
    case "encrypt-file": pipeFile(new vpqc.StreamEncryptor(pub(a[0]), enc(a[1])), a[2], a[3]); break;
    case "decrypt-file": pipeFile(new vpqc.StreamDecryptor(sec(a[0]), enc(a[1])), a[2], a[3]); break;
    default: throw new Error(`unknown command ${cmd}`);
  }
} catch (e) {
  console.error(`node-driver: ${e.message}`);
  process.exit(1);
}
