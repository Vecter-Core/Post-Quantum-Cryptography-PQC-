# @vpqc/core (JavaScript / TypeScript)

Post-quantum cryptography with safe defaults, compiled to WebAssembly from the Rust core.
**Pre-release, unaudited: do not protect real secrets with it yet.**

```js
// Node.js (CommonJS)
const vpqc = require("@vpqc/core");

const keys = vpqc.generateEncryptionKeypair();            // "standard": X-Wing (X25519 + ML-KEM-768)
const enc = new TextEncoder(), dec = new TextDecoder();
const sealed = vpqc.seal(keys.publicKey, enc.encode("secret"), enc.encode("ctx"));
dec.decode(vpqc.unseal(keys.secretKey, sealed, enc.encode("ctx"))); // "secret"

const signer = vpqc.generateSigningKeypair();             // Ed25519 + ML-DSA-65 composite
const sig = vpqc.sign(signer.secretKey, enc.encode("release"), enc.encode("my-app/v1"));
vpqc.verify(signer.publicKey, enc.encode("release"), enc.encode("my-app/v1"), sig); // throws if invalid
```

Browsers and edge runtimes (ES modules) must initialise the module first:

```js
import init, * as vpqc from "@vpqc/core";
await init();
```

Errors are `Error` objects with `name === "VpqcError"` and `code` one of
`DECRYPTION_FAILED`, `VERIFICATION_FAILED`, `INVALID_INPUT`, `BACKEND`.

Build: `rustup target add wasm32-unknown-unknown && cargo install wasm-bindgen-cli --version 0.2.129 && npm run build`.
Randomness comes from `crypto.getRandomValues` (Node.js 19+ and all modern browsers).
Note: JavaScript cannot guarantee memory zeroization of key material.
