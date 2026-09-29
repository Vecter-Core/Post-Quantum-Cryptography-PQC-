import pytest

import vpqc


def test_encrypt_round_trip_all_profiles():
    for profile in ("standard", "fast-auth", "cnsa2", "high"):
        keys = vpqc.generate_encryption_keypair(profile)
        sealed = vpqc.seal(keys.public, b"secret", aad=b"ctx")
        assert vpqc.unseal(keys.secret, sealed, aad=b"ctx") == b"secret"


def test_wrong_aad_and_key_fail():
    a = vpqc.generate_encryption_keypair()
    b = vpqc.generate_encryption_keypair()
    sealed = vpqc.seal(a.public, b"secret", aad=b"one")
    with pytest.raises(vpqc.DecryptionError):
        vpqc.unseal(a.secret, sealed, aad=b"two")
    with pytest.raises(vpqc.DecryptionError):
        vpqc.unseal(b.secret, sealed, aad=b"one")


def test_tampering_is_detected():
    keys = vpqc.generate_encryption_keypair()
    sealed = bytearray(vpqc.seal(keys.public, b"secret"))
    for i in (0, 6, 12, 500, len(sealed) - 1):
        bad = bytearray(sealed)
        bad[i] ^= 1
        with pytest.raises(vpqc.VpqcError):
            vpqc.unseal(keys.secret, bad)


def test_sign_verify():
    for profile in ("standard", "fast-auth", "cnsa2", "high"):
        keys = vpqc.generate_signing_keypair(profile)
        sig = vpqc.sign(keys.secret, b"msg", context=b"app/v1")
        vpqc.verify(keys.public, b"msg", sig, context=b"app/v1")
        assert vpqc.is_valid(keys.public, b"msg", sig, context=b"app/v1")
        assert not vpqc.is_valid(keys.public, b"msg", sig, context=b"app/v2")
        assert not vpqc.is_valid(keys.public, b"other", sig, context=b"app/v1")
        with pytest.raises(vpqc.VerificationError):
            vpqc.verify(keys.public, b"msg", sig, context=b"app/v2")


def test_context_is_required_and_bounded():
    keys = vpqc.generate_signing_keypair()
    with pytest.raises(TypeError):
        vpqc.sign(keys.secret, b"msg")  # type: ignore[call-arg]
    with pytest.raises(vpqc.InvalidInputError):
        vpqc.sign(keys.secret, b"msg", context=b"x" * 256)


def test_errors_hierarchy():
    assert issubclass(vpqc.DecryptionError, vpqc.VpqcError)
    assert issubclass(vpqc.VerificationError, vpqc.VpqcError)
    assert issubclass(vpqc.InvalidInputError, ValueError)


def test_wrong_key_kind_is_invalid_input():
    enc = vpqc.generate_encryption_keypair()
    sig = vpqc.generate_signing_keypair()
    with pytest.raises(vpqc.InvalidInputError):
        vpqc.seal(sig.public, b"x")
    with pytest.raises(vpqc.InvalidInputError):
        vpqc.sign(enc.secret, b"x", context=b"c")
    with pytest.raises(vpqc.InvalidInputError):
        vpqc.PublicKey(b"garbage")


def test_unknown_profile():
    with pytest.raises(ValueError):
        vpqc.generate_encryption_keypair("nope")


def test_key_serialization():
    keys = vpqc.generate_encryption_keypair()
    assert vpqc.PublicKey.from_text(keys.public.to_text()) == keys.public
    assert vpqc.PublicKey.from_bytes(keys.public.to_bytes()) == keys.public
    sk = vpqc.SecretKey.from_text(keys.secret.to_text())
    assert vpqc.unseal(sk, vpqc.seal(keys.public, b"x")) == b"x"
    assert "redacted" in repr(keys.secret) and "redacted" in str(keys.secret)
    assert keys.public.algorithm.startswith("X-Wing")


def test_accepts_bytes_like():
    keys = vpqc.generate_encryption_keypair()
    sealed = vpqc.seal(keys.public, bytearray(b"abc"), aad=memoryview(b"ctx"))
    assert vpqc.unseal(keys.secret, memoryview(sealed), aad=b"ctx") == b"abc"


def test_large_message():
    keys = vpqc.generate_encryption_keypair()
    data = bytes(range(256)) * 4096
    assert vpqc.unseal(keys.secret, vpqc.seal(keys.public, data)) == data


def test_profiles():
    names = {p["name"] for p in vpqc.profiles()}
    assert names == {"standard", "fast-auth", "cnsa2", "high"}


def test_interop_with_c_abi_format(tmp_path):
    """Sealed boxes from Python must be readable by the Rust CLI, and vice versa."""
    import shutil
    import subprocess
    import os

    cli = os.environ.get("VPQC_CLI") or shutil.which("vpqc")
    if not cli:
        pytest.skip("vpqc CLI not available (set VPQC_CLI)")
    keys = vpqc.generate_encryption_keypair()
    (tmp_path / "k.pub").write_text(keys.public.to_text())
    (tmp_path / "k.sec").write_text(keys.secret.to_text())
    # CLI seals, Python opens.
    (tmp_path / "in.txt").write_bytes(b"from the cli")
    subprocess.run([cli, "seal", "--to", str(tmp_path / "k.pub"), "--aad", "x",
                    "-o", str(tmp_path / "out.sealed"), str(tmp_path / "in.txt")], check=True)
    assert vpqc.unseal(keys.secret, (tmp_path / "out.sealed").read_bytes(), aad=b"x") == b"from the cli"
    # Python seals, CLI opens.
    (tmp_path / "py.sealed").write_bytes(vpqc.seal(keys.public, b"from python", aad=b"y"))
    res = subprocess.run([cli, "open", "--key", str(tmp_path / "k.sec"), "--aad", "y",
                          str(tmp_path / "py.sealed")], check=True, capture_output=True)
    assert res.stdout == b"from python"
