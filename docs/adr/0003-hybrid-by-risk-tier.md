# ADR-0003: Hybrid only where the quantum threat is real

- Status: accepted
- Date: 2026-09-29

## Decision
| Use | Choice | Reason |
|---|---|---|
| Key establishment / encryption to a recipient | **Always hybrid** (X-Wing: X25519 + ML-KEM-768) in `standard` and `fast-auth` | Harvest-now-decrypt-later is a present threat |
| Long-lived signatures | **Composite** Ed25519 + ML-DSA-65 in `standard` | Forgery must remain infeasible for years |
| Short-lived authentication | Classical Ed25519 allowed (`fast-auth`) | Attacker needs a quantum computer *during* the session |
| Symmetric crypto, hashes | Unchanged: ChaCha20-Poly1305, SHA-3/SHAKE | 256-bit keys survive Grover |
| Compliance profile | `cnsa2`: ML-KEM-1024 and ML-DSA-87 without classical part | CNSA 2.0 requires pure PQC at these levels |

`vpqc inspect` prints a `CLASSICAL ONLY` warning for classical-only keys.

## Consequences
- Larger keys and signatures in `standard` (1216-byte public key, 3373-byte signature).
- The X-Wing combiner is used exactly as specified, since its security proof is specific to
  that construction. New hybrid pairs need their own reviewed combiner.
