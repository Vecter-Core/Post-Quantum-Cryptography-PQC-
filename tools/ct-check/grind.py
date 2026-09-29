#!/usr/bin/env python3
"""Secret-independence check under valgrind memcheck ("ctgrind").

Builds vpqc-ct-check with line tables (so inlined frames are named), runs every case of
`vpqc-ct-check --valgrind <case>` under memcheck with the secret key bytes marked undefined,
and requires every report to match an entry in ALLOWED below. Each allowed entry is a place
where a branch on secret-derived data is expected, with the reason. Anything else fails.

    python3 tools/ct-check/grind.py            # from the repository root; needs valgrind
"""

import os
import re
import subprocess
import sys

# Regexes over the report's stack, written "innermost <- caller <- ...". Every report of the
# case must match one of the case's entries.
ALLOWED = {
    # Must be reported: proves the pipeline detects a secret-dependent branch.
    "control-leaky-compare": [(r"leaky_eq", "deliberate early-exit compare (control)")],
    "xwing-decaps": [
        (r"sample_matrix_A",
         "X-Wing re-derives the ML-KEM key from its 32-byte seed; matrix A is rejection-sampled "
         "from rho, which is derived from the seed but published in the public key"),
    ],
    "mlkem1024-p384-decaps": [
        (r"sample_matrix_A", "as for X-Wing: rho is public"),
        (r"neg_mod.*LookupTable.*select",
         "P-384 table lookup negates the selected point; LLVM turns crypto-bigint's branch-free "
         "is_zero(y) into a branch. y is never 0 on a prime-order curve, so the branch always "
         "goes the same way"),
        (r"SecretKey::from_(bytes|slice)|from_bytes <- (elliptic_curve::secret_key|from_slice)",
         "scalar validity check (0 < d < n); failure probability about 2^-384"),
        (r"to_sec1_bytes", "encoding the P-384 public key share (public output)"),
    ],
    "ecdsa-p384-sign": [
        (r"neg_mod.*LookupTable.*select", "see mlkem1024-p384-decaps"),
        (r"SecretKey::from_(bytes|slice)|from_bytes <- (elliptic_curve::secret_key|from_slice)",
         "scalar validity check (0 < d < n)"),
        (r"fill_next_k", "RFC 6979 candidate k range check; retry probability about 2^-384"),
        (r"invert <- sign_prehashed", "k != 0 check on the inverse"),
        (r"from_scalars <- sign_prehashed|into_option <- (from_slice <- from_scalars|sign_prehashed)",
         "r != 0 and s != 0 checks of ECDSA"),
    ],
    "mldsa65-sign": [
        (r"vector_infinity_norm_exceeds <- sign_internal|^sign_internal",
         "FIPS 204 rejection conditions (norms of z, r0, c*t0 and the hint count); leaking "
         "which candidate was rejected is allowed, rejected candidates are discarded"),
        (r"sample_challenge_ring_element", "SampleInBall on c~, which is part of the signature"),
        (r"serialize <- sign_internal", "encoding the signature (public output)"),
    ],
}
# Cases not listed must produce no report at all.

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TARGET = os.path.join(ROOT, "target", "ct-grind")
BIN = os.path.join(TARGET, "release", "vpqc-ct-check")


def build():
    env = dict(os.environ, CARGO_PROFILE_RELEASE_DEBUG="line-tables-only", CARGO_TARGET_DIR=TARGET)
    subprocess.run(["cargo", "build", "--release", "-q", "-p", "vpqc-ct-check"], cwd=ROOT, env=env,
                   check=True)


def reports(case):
    out = subprocess.run(
        ["valgrind", "-q", "--num-callers=16", BIN, "--valgrind", case],
        capture_output=True, text=True, check=False)
    if out.returncode != 0 and "==" not in out.stderr:
        sys.exit(f"{case}: run failed:\n{out.stderr}")
    blocks = re.split(r"\n==\d+== \n", out.stderr)
    for block in blocks:
        if "uninitialised" not in block:
            continue
        frames = re.findall(r"(?:at|by) 0x[0-9A-F]+: (.+?)(?: \([^()]*\))?$", block, re.M)
        yield " <- ".join(strip_generics(f) for f in frames), block


def strip_generics(frame):
    """`a::B<C<D>>::f<E>` -> `a::B::f`, keeping the path.

    Qualified forms, as printed by some rustc/valgrind versions, keep their type path:
    `<a::B<C>>::f` -> `a::B::f` and `<a::B as c::T>::f` -> `a::B as c::T::f`.
    """
    if frame.startswith("<"):
        depth = 0
        for i, ch in enumerate(frame):
            depth += {"<": 1, ">": -1}.get(ch, 0)
            if depth == 0:
                frame = frame[1:i] + frame[i + 1:]
                break
    while True:
        shorter = re.sub(r"<[^<>]*>", "", frame)
        if shorter == frame:
            return frame
        frame = shorter


def main():
    build()
    cases = subprocess.run([BIN, "--valgrind", "list"], capture_output=True, text=True,
                           check=True).stdout.split()
    failed = False
    for case in cases:
        rules = ALLOWED.get(case, [])
        seen, unexpected = {}, []
        for stack, block in reports(case):
            for pattern, _ in rules:
                if re.search(pattern, stack):
                    seen[pattern] = seen.get(pattern, 0) + 1
                    break
            else:
                unexpected.append((stack, block))
        total = sum(seen.values()) + len(unexpected)
        if case.startswith("control"):
            ok = total > 0 and not unexpected
            status = "detected (expected: control)" if ok else "NOT DETECTED: pipeline broken"
        else:
            ok = not unexpected
            status = "clean" if total == 0 else (
                f"{total} reports, all allowed" if ok else f"{len(unexpected)} UNEXPECTED")
        print(f"{case:<26} {status}")
        for pattern, reason in rules:
            if seen.get(pattern) and not case.startswith("control"):
                print(f"    {seen[pattern]:>3} x {reason}")
        for stack, _ in unexpected:
            print(f"    unexpected: {stack[:300]}")
        for _, block in unexpected[:2]:
            print("\n".join(block.splitlines()[:14]) + "\n    ...")
        failed |= not ok
    print("\nFAILED" if failed else "\nAll cases as expected.")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
