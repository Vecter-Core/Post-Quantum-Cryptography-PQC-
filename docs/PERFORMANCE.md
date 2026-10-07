# Performance and sizes

Measured, not estimated. Latency depends on the machine: use these numbers for **relative**
comparisons between profiles and for sizing, not as a benchmark against other libraries.

Reproduce: `cargo bench -p vpqc --bench profiles` (criterion; prints the size table first).

## Sizes (bytes, encoded with the vpqc header)

| Profile | Encryption public key | Encryption secret key (seed) | Sealed box overhead (empty message) | Signing public key | Signing secret key (seed) | Signature |
|---|--:|--:|--:|--:|--:|--:|
| `standard` (X-Wing; Ed25519 + ML-DSA-65) | 1232 | 48 | 1147 | 2000 | 48 | 3385 |
| `fast-auth` (X-Wing; Ed25519 only) | 1232 | 48 | 1147 | 48 | 48 | 76 |
| `cnsa2` (ML-KEM-1024; ML-DSA-87) | 1584 | 80 | 1595 | 2608 | 48 | 4639 |
| `high` (P-384 + ML-KEM-1024; ECDSA-P384 + ML-DSA-87) | 1681 | 48 | 1692 | 2705 | 48 | 4735 |

Secret keys are stored as seeds, so they stay small (ADR-0004); the expanded keys are derived
in memory. For reference, classical sizes: X25519 public key 32, Ed25519 signature 64,
ECDSA P-256 signature 64, RSA-2048 signature 256.

### Sizes in the standard formats (ML-DSA-65 unless noted)

| Object | Size |
|---|--:|
| COSE_Sign1 / CWT with a short payload | about 3.35 KB |
| JWT (compact JWS, base64url) | about 4.5 KB |
| Public COSE_Key | 1962 B (ML-DSA-87: 2602 B) |
| X.509 end-entity certificate | 5.6 KB signed by ML-DSA-65, 6.9 KB signed by ML-DSA-87 |
| X.509 ML-DSA-87 CA certificate | 7.5 KB |
| Leaf + intermediate (root excluded), on the wire | about 14 KB |
| TLS 1.3 `X25519MLKEM768` key share | client 1216 B, server 1120 B (vs 32 B for X25519) |

Where this matters: single-datagram protocols (DNS, CoAP without block-wise transfer,
LoRaWAN, 802.15.4 frames), HTTP headers (typical proxy limit 8 KB: a JWT uses more than half),
constrained devices (certificate chains), and any protocol with a handshake size budget.
Mitigations are protocol-specific (cached or compressed certificates, signing at a gateway,
keeping a classical signature on a constrained link while the long-lived trust uses ML-DSA).

## Latency

One run of `cargo bench -p vpqc --bench profiles -- --sample-size 30 --measurement-time 2`:
Intel Xeon @ 2.80 GHz, 4 vCPUs of a shared cloud VM, x86_64, Linux, release build, the
benchmark pinned to one core while other jobs were running on the machine (so, noisy). Median
of the criterion interval, messages of 1 KiB.

| Profile | KEM keygen | seal | open | Sign keygen | sign | verify |
|---|--:|--:|--:|--:|--:|--:|
| `standard` | 87 µs | 152 µs | 175 µs | 115 µs | 376 µs | 163 µs |
| `fast-auth` | 88 µs | 175 µs | 168 µs | 21 µs | 49 µs | 60 µs |
| `cnsa2` | 34 µs | 42 µs | 80 µs | 122 µs | 436 µs | 137 µs |
| `high` | 714 µs | 1.37 ms | 1.39 ms | 791 µs | 1.73 ms | 895 µs |

Reading the table:

- The cost of post-quantum security is small in time (tens to hundreds of microseconds) and large
  in bytes: the network and storage footprint is the real price, not the CPU.
- `fast-auth` signing is about 8 times faster than `standard` and verification about 3 times:
  it is classical Ed25519, meant only for short-lived authentication.
- `high` is 4 to 9 times slower than `standard` in these runs. The P-384 component is a
  RustCrypto implementation without vectorised code, which probably explains most of it (not
  profiled). It is for long-lived data, not for hot paths.
- ML-DSA signing time varies from call to call (rejection sampling; FIPS 204), so look at
  medians and tails, not a single run.

Not measured here: streaming throughput on large files (about 500 MiB/s in memory in an earlier
run, ROADMAP), ARM/NEON, Windows and macOS, and the TLS sidecar's handshake latency.
