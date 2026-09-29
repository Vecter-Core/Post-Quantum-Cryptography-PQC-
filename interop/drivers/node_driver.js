// Node.js driver for the interoperability suite. See interop/run.sh.
const fs = require("node:fs");
const path = require("node:path");
const vpqc = require(path.join(__dirname, "../../bindings/js/pkg/node/vpqc.js"));

const [cmd, ...a] = process.argv.slice(2);
const read = (p) => new Uint8Array(fs.readFileSync(p));
const enc = (s) => new TextEncoder().encode(s);
const pub = (p) => vpqc.publicKeyFromText(fs.readFileSync(p, "utf8"));
const sec = (p) => vpqc.secretKeyFromText(fs.readFileSync(p, "utf8"));

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
    default: throw new Error(`unknown command ${cmd}`);
  }
} catch (e) {
  console.error(`node-driver: ${e.message}`);
  process.exit(1);
}
