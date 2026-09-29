Official NIST ACVP test vectors from <https://github.com/usnistgov/ACVP-Server>
(`gen-val/json-files/<name>/internalProjection.json`), fetched 2026-09-29.

Filtered (test groups removed, tests unmodified) to what vpqc uses:
- ML-KEM-768 and ML-KEM-1024 (ML-KEM-512 is not enabled). The `decapsulationKeyCheck` groups are
  dropped: vpqc stores ML-KEM secret keys as 64-byte seeds and never accepts an expanded
  decapsulation key from outside, so the check does not apply.
- ML-DSA-65 and ML-DSA-87 (ML-DSA-44 is not enabled), and for sigGen/sigVer only the
  `external` / `pure` interface: vpqc does not use HashML-DSA (pre-hash) or the internal
  (`mu`) interface.
