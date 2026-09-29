# Constant-time checks

Two complementary checks of the operations that handle secrets. Both are **evidence, not
proof**: they cover the code paths and the machine they run on.

## 1. Secret tracking under valgrind (`grind.py`, gates CI)

```sh
python3 tools/ct-check/grind.py        # needs valgrind; about one minute
```

The "ctgrind" technique: each case marks the secret key bytes as *undefined* with a valgrind
client request, and memcheck reports every conditional branch and every memory address computed
from them, which are the two ways code leaks secrets through timing and cache. It has no noise,
so it can gate CI. It does not see variable-latency instructions (for example division on some
CPUs) or effects below the instruction level.

Every report must match an entry in `ALLOWED` in `grind.py`, which records why that branch is
acceptable. A `control-leaky-compare` case must be reported, proving the pipeline works.

Result on x86_64 with AVX2 (libcrux takes its AVX2 path):

| Case | Result |
|------|--------|
| ML-KEM-768 decaps (valid and invalid ciphertext), ML-KEM-1024 decaps | **clean**: nothing depends on `s` or `z` |
| X25519, Ed25519 sign, ChaCha20-Poly1305 seal | **clean** |
| X-Wing decaps, MLKEM1024-P384 decaps | only rejection sampling of matrix A from `rho`. The key is re-derived from its seed, so `rho` is seed-derived, but it is published in the public key |
| ML-DSA-65 sign | only the FIPS 204 rejection conditions (norms of z, r0, c·t0, hint count), SampleInBall on c̃, and signature encoding: all allowed by FIPS 204 or public output |
| ECDSA-P384 sign, P-384 in MLKEM1024-P384 | validity checks with failure probability ≈ 2⁻³⁸⁴ (scalar range, RFC 6979 `k`, r and s ≠ 0), and one compiler-introduced branch, below |

**Findings.**

1. *Fixed:* the workspace release profile had `overflow-checks = true`, which Cargo applies to
   every dependency. It added a `jo`/`jb` panic branch to every field multiplication on secret
   data in curve25519-dalek, p384 and libcrux (about 1000 reports for X25519 alone). The branches
   are never taken, so the practical timing effect is negligible. Still, they are branches on
   secrets that the libraries' constant-time design does not expect. Overflow checks now stay on
   for vpqc's own crates and are off for dependencies (`[profile.release.package."*"]`), in the
   workspace and in the Python and JS bindings. Re-enabling them makes `grind.py` fail.
2. *Upstream, harmless in practice:* in p384's `LookupTable::select` (via primeorder), LLVM
   compiles crypto-bigint's branch-free `is_zero` in the conditional negation `neg_mod(y)` into a
   `je`. The branch tests `y == 0` for the selected table point. That never happens on a
   prime-order curve (the identity is (0 : 1 : 0)), so the branch always goes the same way. Worth
   reporting to RustCrypto; it is allowlisted with that reason.

## 2. Timing measurements (dudect style, run by hand)

```sh
cargo run --release -p vpqc-ct-check -- [samples]                 # default 200000
cargo run --release -p vpqc-ct-check -- --fixed-inputs [samples]  # informational
```

Two input classes are timed in random interleaved order and compared with Welch's t-test after
cropping at several percentiles; `|t| > 4.5` means the class changes the timing. Deliberately
leaky **controls** must be detected, or the run fails: a 1024-byte early-exit compare, a 16-byte
one (tag size), and an ML-KEM decapsulation followed by an early-exit comparison of the
re-encrypted ciphertext (the classic Fujisaki–Okamoto implementation mistake, a few ns hidden
under ~27 µs of decapsulation).

Gating checks (2 × 10⁶ samples, a shared cloud VM, x86_64): ML-KEM-768 and X-Wing decapsulation
of **pools of 512 valid vs 512 corrupted ciphertexts** (FIPS 203 implicit rejection must not
reveal validity), X25519 with two scalars, and the ChaCha20-Poly1305 tag check (tag wrong at the
first vs the last byte). All are below 4.5 (1.3 to 3.0) while every control is detected (|t| 109
to 42000).

**Fixed-input comparisons (informational, why the gate uses pools).** Comparing two *specific*
inputs is sensitive to any data dependence, including on public data. On a VM it also gives
false positives: the ChaCha20 reference, constant time by construction, reached |t| = 6.7. For
ML-KEM-768 decapsulation:

- two valid ciphertexts gave |t| from 0.8 to 21 across runs and pairs;
- the same ciphertext and public key with **only the secret part `s`, `z` changed** gave |t|
  10 to 18 in two of three runs (2.8 to 3.9 in the third), a difference of tens of ns out of ~27 µs (≈0.1 %).

Secret tracking (section 1) shows no branch and no memory address depending on `s` or `z`, so
this is not a leak of either kind. What remains is instruction-level or microarchitectural data
dependence, which only cycle-accurate measurement on bare metal (pinned core, fixed frequency)
can settle. It is recorded as an open item for the external audit (ROADMAP phase 5), not
dismissed.
