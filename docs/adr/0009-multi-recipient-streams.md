# ADR-0009: Multi-recipient streams (envelope encryption)

- Status: accepted
- Date: 2026-09-29

## Context
The stream format of ADR-0007 has exactly one recipient. Real deployments need more than one
key able to decrypt the same data:
- a backup readable by the operator and by an offline recovery (escrow) key;
- a file shared by a team;
- the KMS pattern, where a data key is wrapped for one or more key-encryption keys, so that
  keys can rotate or be revoked without re-encrypting the data.

Encrypting the data once per recipient multiplies storage and time, and makes it hard to
guarantee that every recipient gets the same content.

## Decision
A new object kind `6`. The body is the same STREAM construction as ADR-0007; only the header
differs:

```text
header      = "VPQC" 01 06 aead_id:u8 chunk_log:u8 n:u8          (1 <= n <= 32)
              n x ( kem_id:u16 ct_len:u16 | kem_ct | wrapped_key[48] )
              header_mac[32]
file_key    = 32 random bytes
wrap_key_i  = SHAKE256("vpqc-recipient-v1" || be64(2) || kem_id || be64(len(ct_i)) || ct_i || ss_i)[..32]
wrapped_i   = ChaCha20-Poly1305(wrap_key_i, nonce = 0, ad = "", file_key)
header_mac  = SHAKE256("vpqc-header-mac-v1" || be64(len(h)) || h || be64(len(aad)) || aad || file_key)[..32]
              where h = header bytes before the MAC
payload_key = SHAKE256("vpqc-multistream-v1" || be64(8) || P || be64(len(aad)) || aad || file_key)[..32]
              where P = the first 8 header bytes ("VPQC" 01 06 aead_id chunk_log)
```

- Each recipient's KEM is independent: recipients of different profiles can be mixed. Each
  wrap key is used once, so the zero nonce is safe.
- **The header MAC commits to the file key.** ChaCha20-Poly1305 is not key-committing, so
  without the MAC a malicious sender could give recipients different file keys, together with
  a payload valid under several keys ("invisible salamanders"), and show each recipient
  different content. The MAC is a SHAKE256 keyed hash of the file key, and cannot hold for two
  keys. A decryptor whose stanza unwraps but whose MAC fails rejects the file; it does not
  try other stanzas.
- The payload key binds the stream parameters and the caller's `aad`, but **not the
  stanzas**. The stanzas are authenticated by the header MAC: only a holder of the file key
  can produce a valid header, so changing, reordering or splicing stanzas fails for everyone.
  Because the payload key does not depend on the stanzas, a current recipient can **re-wrap**
  the file for a new recipient list without touching the body (key rotation, adding or
  removing recipients). This is the KMS "re-wrap the data key" operation. It gives no new
  power: any recipient already knows the file key and could re-encrypt the content anyway.
  (A first draft bound the whole header into the payload key; that made re-wrapping
  impossible and was changed before release.)
- Stanzas carry no recipient identifier. A decryptor tries every stanza of its KEM, at most
  32 decapsulations. The header reveals the number of recipients and their KEM algorithms,
  but not who they are.
- The encryptor rejects duplicate recipients, more than 32 recipients, and keys that are not
  encryption keys.
- Decryption detects the kind automatically. With one recipient, `vpqc encrypt` and the
  single-key APIs keep writing kind 5, so existing files and readers are unaffected.

## Consequences
- Every binding decrypts multi-recipient files with no API change, because they all use the
  shared Rust decryptors. Multi-recipient encryption is exposed in Rust
  (`Encryptor::to_recipients`, `encrypt_file_multi`), the CLI (`--to` repeated), C
  (`vpqc_encrypt_file_multi`), Python (a list of keys), Go (`EncryptFileMulti`), Java
  (`encryptFileMulti`), PHP (`encryptFileMulti`), Ruby (`encrypt_file_multi`) and JS
  (`new StreamEncryptor([...keys])`).
- Any recipient can decrypt, but, as with any public-key encryption without sender
  authentication, cannot tell who created the file. Sign the file if origin matters.
- `rewrap` / `vpqc rewrap` change the recipients without re-encrypting. They are exposed in
  every language: Rust, CLI, C, Python, Go, Java, PHP, Ruby, and JS on bytes. Removing a
  recipient this way stops them from opening the *new* file only. They may keep the old
  file or the file key, so revoking access to data they already had needs re-encryption.
- `vpqc encrypt --envelope` (and the equivalent single-key calls of the multi APIs) writes this
  format for one recipient, so that the key can be rotated later. Plain single-recipient files
  (kind 5) cannot be re-wrapped; they have no file key.
- As in ADR-0007, the regression vector (`crates/vpqc/tests/data/multistream-v1.json`) is
  self-generated. It guards compatibility across versions and languages, and the cross-language
  suite checks it in every implementation.
