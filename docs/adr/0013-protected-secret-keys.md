# ADR-0013: Secret keys protected at rest (passphrase, KMS, HSM, TPM)

- Status: accepted
- Date: 2026-09-29

## Context
Until now, `.vpqc-secret` files held the key seed unencrypted and relied only on file mode
0600. A copied backup, a leaked disk image or a mis-set permission then exposes the key.
Every post-quantum algorithm is worthless if the key sits in plaintext.

Organisations already keep root secrets in a KMS (AWS KMS, Google Cloud KMS, HashiCorp Vault /
OpenBao), in a TPM, or behind a passphrase. The ROADMAP item "envelope encryption for KMS"
asks for exactly that integration. Wrapping data keys under hybrid keys is already covered by
the multi-recipient format (ADR-0009).

On quantum resistance, the symmetric wrapping used by these services does not depend on a
quantum-vulnerable problem:
- AWS KMS and Google Cloud KMS symmetric keys use AES-256-GCM inside the HSM;
- Vault Transit uses AES-256-GCM96 by default;
- systemd-creds uses AES-256-GCM, with the host key and/or TPM2 sealing;
- Argon2id with XChaCha20-Poly1305 has a 256-bit key.

At most Grover applies, which leaves about 128-bit security.

## Decision
- **New object, kind 7, "protected secret key":**

  ```text
  "VPQC" 01 07 method:u8 params_len:u16 params | nonce:24 | ciphertext
  ```

  - `ciphertext` is XChaCha20-Poly1305 over the ordinary secret key object (kind 4).
  - **Every preceding byte is the associated data**, so the method, the parameters, the
    wrapped key and the nonce cannot be changed without detection.
  - Armor label: `VPQC PROTECTED SECRET KEY`.
  - A random 192-bit nonce comes with every write, so re-protecting never reuses a nonce.
- **Method 1, passphrase.** Argon2id (RFC 9106, version 0x13, 32-byte output) with a random
  16-byte salt.
  - Default parameters are RFC 9106's second recommended option: 64 MiB, 3 passes, 4 lanes.
  - Readers accept only 8 MiB to 1 GiB, 1 to 16 passes and 1 to 16 lanes. A crafted file
    therefore cannot make `vpqc` allocate or compute without limit, and weak parameters are
    refused.
  - The passphrase is read, in order, from `VPQC_PASSPHRASE_FILE`, `VPQC_PASSPHRASE`, or a
    terminal prompt (asked twice for new keys). Passphrases shorter than 12 characters get a
    warning.
- **Method 2, external key service.** The secret key is encrypted under a random 32-byte KEK,
  and the service wraps that KEK. The file stores the provider, a label (which key) and the
  wrapped blob; the unwrapped KEK is never stored.
  - Providers are `systemd-creds` (TPM2/host key), `aws-kms`, `gcp-kms` and `vault-transit`.
  - `vpqc` runs each service's **official CLI** with a fixed argument list and no shell. The
    CLIs already handle authentication: profiles, roles, workload identity, `VAULT_TOKEN`.
  - AWS calls bind the encryption context `purpose=vpqc-secret-key`.
  - Right after wrapping, `vpqc` unwraps once and compares the result, so a key is never
    written that the service cannot open again.
- **Labels are untrusted input.** A key file can come from anywhere, and its label ends up as
  a command argument:
  - labels are limited to `[A-Za-z0-9._:/-]`, 1 to 256 characters, with no leading `-` and
    no `..`;
  - they are passed as `--option=value`.

  A crafted file therefore cannot inject options (such as `--endpoint-url`) or reach other
  Vault paths (such as `transit/../sys/...`).
- **Library.** The Rust library (`vpqc::protect`) does the cryptography and the format, and
  never spawns processes. Running the service is the caller's job, as the CLI does.
- **Loading is transparent in the CLI.** Every command that takes a secret key accepts a
  protected one. `vpqc inspect` shows the protection without decrypting anything. `vpqc
  protect` / `vpqc unprotect` convert existing files, and `keygen` takes `--passphrase` or
  `--kms`.

## Consequences
- The passphrase format is interop-tested against independent implementations
  (`interop/keyprotect.sh`, 28 checks):
  - argon2-cffi (the Argon2 reference C code) and PyNaCl (libsodium XChaCha20-Poly1305)
    decrypt keys that vpqc protected, for 4 profiles, and get vpqc's exact plain key;
  - vpqc opens keys that they protected;
  - a wrong passphrase and a 4 GiB memory parameter are rejected.
- `systemd-creds` was tested for real on systemd 255, with the host key.
- The AWS, GCP and Vault paths are tested against stand-in CLIs that accept only the exact
  expected argument lists. This checks vpqc's side of each contract, not the services
  themselves. They have not been run against live accounts in this repository, so validate
  them once in your environment (`vpqc protect ... --kms`, then `vpqc inspect` and a decrypt).
- The AWS provider reads the KEK through `fileb:///dev/stdin`, so it works on Unix-like
  systems only.
- The format fuzz target covers the new object (strict parse, re-encoding) and asserts that
  no fuzzed file opens under a fixed KEK.
- Not in this step:
  - language bindings, which still load plain keys (the Rust API and the CLI support
    protected keys);
  - PKCS#11 HSMs;
  - Azure Key Vault: its keys are RSA, so wrapping with them would put a quantum-vulnerable
    step back in. Managed HSM with `A256GCM` could be added later.
