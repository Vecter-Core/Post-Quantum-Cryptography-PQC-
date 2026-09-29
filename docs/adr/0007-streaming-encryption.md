# ADR-0007: Streaming encryption for large files

- Status: accepted
- Date: 2026-09-29

## Context
`seal`/`open` (ADR-0005) hold the whole message in memory, which does not work for backups,
disk images or logs of many gigabytes. Streaming must keep memory constant while preserving
the guarantees of the sealed box: confidentiality, integrity, binding of the algorithm ids and
the caller's context, and detection of truncation, reordering and appended data.

## Decision
A new object kind `5` (stream) using the STREAM construction of Hoang, Reyhanitabar, Rogaway
and Vizár ("online authenticated encryption"), in the same form as `age`:

```text
header  = "VPQC" 01 05 kem_id:u16 aead_id:u8 chunk_log:u8 ct_len:u16 | kem_ct
key     = SHAKE256("vpqc-stream-v1" || be64(len(header)) || header
                   || be64(len(aad)) || aad || kem_shared_secret)[0..32]
chunk_i = ChaCha20-Poly1305(key, nonce_i, ad = "", plaintext_i)      (plaintext_i <= 2^chunk_log bytes)
nonce_i = be88(i) || last_flag                                          (last_flag = 0x01 on the final chunk)
stream  = header || chunk_0 || chunk_1 || ... || chunk_n
```

Rules:
- Every chunk except the last has exactly `2^chunk_log` plaintext bytes. The last chunk has
  between 1 and `2^chunk_log` bytes; it is empty only when the whole plaintext is empty.
- The reader decides that a chunk is final only by reaching end of input, and requires the
  final chunk to carry `last_flag = 1`. Hence dropping chunks at the end (truncation), adding
  bytes after the final chunk, or reordering chunks all fail authentication.
- The header and the caller's `aad` are bound through the key derivation, so changing an
  algorithm id, the chunk size, the KEM ciphertext or the context yields a different key and
  the first chunk fails.
- The key is unique per stream (fresh KEM shared secret), so deterministic counter nonces
  never repeat under one key.
- `chunk_log` defaults to 16 (64 KiB) and must be in 10..=24, bounding reader memory at 16 MiB
  even for hostile input.

## Consequences
- A streaming decryptor necessarily releases plaintext before it has seen the end of the
  stream. Each released chunk is authentic, but the stream may still turn out truncated.
  The file-level API (`decrypt_file`, `vpqc decrypt`) therefore writes to a temporary file and
  renames it only after the final chunk verifies; on failure the temporary file is deleted.
  Callers of the `Read`-based API must discard output when an error is returned.
- This is a vpqc construction (like the sealed box), not an IETF standard. Its regression
  vectors in `crates/vpqc/tests/data/` are self-generated: they protect compatibility across
  versions and languages, they are not an independent correctness check. The primitives inside
  (X-Wing / ML-KEM, SHAKE256, ChaCha20-Poly1305) are independently verified elsewhere.
- The sealed box stays the format for messages that fit in memory; both are accepted by
  `vpqc inspect`.
