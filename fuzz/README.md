# Fuzzing

Coverage-guided fuzzing with `cargo-fuzz` (libFuzzer + AddressSanitizer). Requires nightly.

| Target | Checks |
|---|---|
| `parse_formats` | every parser: no panic; anything that parses re-encodes to the same bytes |
| `sealed_box` | hostile `open` never panics; seal/open round trip; any byte flip rejected |
| `stream` | `Decryptor` and `PushDecryptor` agree on every input (differential); round trip with any chunk size / write pattern; flips and truncation rejected |
| `signatures` | hostile signatures never verify or panic; sign/verify round trip; modified signature, message or context rejected |
| `hpke` | hostile `enc`/ciphertext never panics; round trip for every KEM × KDF × AEAD |
| `scan` | certificate / key / source parsing of arbitrary content never panics; reports serialise |

```sh
cargo install cargo-fuzz
cargo test --manifest-path fuzz/Cargo.toml --test gen_corpus -- --ignored   # regenerate fuzz/seeds
cd fuzz && cargo +nightly fuzz run stream corpus/stream seeds/stream -- -max_total_time=600
```

Seeds in `seeds/` are valid objects for the fixed fuzzing keys (see `src/lib.rs`), so the fuzzer
starts inside deep states (multi-chunk streams, composite signatures). `corpus/` is the
fuzzer's working corpus and is not committed. CI runs every target for a short time on each push.
