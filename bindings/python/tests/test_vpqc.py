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


def test_file_streaming(tmp_path):
    keys = vpqc.generate_encryption_keypair()
    data = bytes(range(256)) * 20_000  # ~5 MiB, several chunks
    src, enc, out = tmp_path / "in.bin", tmp_path / "in.bin.vpqc", tmp_path / "out.bin"
    src.write_bytes(data)
    assert vpqc.encrypt_file(keys.public, src, enc, aad=b"backup") == len(data)
    assert vpqc.decrypt_file(keys.secret, enc, out, aad=b"backup") == len(data)
    assert out.read_bytes() == data

    # Wrong context or truncation: DecryptionError and no output file.
    with pytest.raises(vpqc.DecryptionError):
        vpqc.decrypt_file(keys.secret, enc, tmp_path / "x.bin", aad=b"other")
    cut = tmp_path / "cut.vpqc"
    cut.write_bytes(enc.read_bytes()[:-50])
    with pytest.raises(vpqc.DecryptionError):
        vpqc.decrypt_file(keys.secret, cut, tmp_path / "y.bin", aad=b"backup")
    assert not (tmp_path / "x.bin").exists() and not (tmp_path / "y.bin").exists()
    assert not [p for p in tmp_path.iterdir() if p.name.endswith(".vpqc-tmp")]

    # File errors are OSError, wrong key kinds are InvalidInputError.
    with pytest.raises(OSError):
        vpqc.encrypt_file(keys.public, tmp_path / "missing", tmp_path / "z")
    with pytest.raises(vpqc.InvalidInputError):
        vpqc.decrypt_file(vpqc.generate_encryption_keypair("cnsa2").secret, enc, tmp_path / "w", aad=b"backup")
    # A stream is not a sealed box.
    with pytest.raises(vpqc.VpqcError):
        vpqc.unseal(keys.secret, enc.read_bytes())


def test_incremental_stream_objects(tmp_path):
    import random
    keys = vpqc.generate_encryption_keypair()
    data = random.Random(1).randbytes(700_000)
    enc = vpqc.StreamEncryptor(keys.public, aad=b"upload")
    ct = b"".join(enc.update(data[i:i + 12_345]) for i in range(0, len(data), 12_345)) + enc.finalize()
    # Interoperable with the file API.
    (tmp_path / "s.vpqc").write_bytes(ct)
    vpqc.decrypt_file(keys.secret, tmp_path / "s.vpqc", tmp_path / "s.out", aad=b"upload")
    assert (tmp_path / "s.out").read_bytes() == data
    dec = vpqc.StreamDecryptor(keys.secret, aad=b"upload")
    out = b"".join(dec.update(ct[i:i + 999]) for i in range(0, len(ct), 999)) + dec.finalize()
    assert out == data
    # Truncation is caught at finalize().
    dec = vpqc.StreamDecryptor(keys.secret, aad=b"upload")
    dec.update(ct[:-10])
    with pytest.raises(vpqc.DecryptionError):
        dec.finalize()
    with pytest.raises(vpqc.VpqcError):
        enc.update(b"after finalize")


def test_multiple_recipients(tmp_path):
    user = vpqc.generate_encryption_keypair()
    recovery = vpqc.generate_encryption_keypair("high")
    outsider = vpqc.generate_encryption_keypair()
    data = bytes(range(256)) * 1000
    src, enc = tmp_path / "in", tmp_path / "in.vpqc"
    src.write_bytes(data)
    assert vpqc.encrypt_file([user.public, recovery.public], src, enc, aad=b"b") == len(data)
    for i, k in enumerate([user, recovery]):
        vpqc.decrypt_file(k.secret, enc, tmp_path / f"out{i}", aad=b"b")
        assert (tmp_path / f"out{i}").read_bytes() == data
    with pytest.raises(vpqc.DecryptionError):
        vpqc.decrypt_file(outsider.secret, enc, tmp_path / "x", aad=b"b")
    # Incremental, and readable by the incremental decryptor of either recipient.
    s = vpqc.StreamEncryptor((user.public, recovery.public), aad=b"s")
    ct = s.update(data) + s.finalize()
    for k in (user, recovery):
        d = vpqc.StreamDecryptor(k.secret, aad=b"s")
        assert b"".join(d.update(ct[i:i + 777]) for i in range(0, len(ct), 777)) + d.finalize() == data
    with pytest.raises(TypeError):
        vpqc.encrypt_file([], src, enc)
    with pytest.raises(vpqc.VpqcError):
        vpqc.encrypt_file([user.public, user.public], src, tmp_path / "dup")


def test_rewrap_for_key_rotation(tmp_path):
    old, new = vpqc.generate_encryption_keypair(), vpqc.generate_encryption_keypair("high")
    src, v1, v2 = tmp_path / "in", tmp_path / "v1", tmp_path / "v2"
    src.write_bytes(b"x" * 100_000)
    vpqc.encrypt_file(old.public, src, v1, aad=b"k", envelope=True)
    vpqc.rewrap_file(old.secret, new.public, v1, v2, aad=b"k")
    vpqc.decrypt_file(new.secret, v2, tmp_path / "out", aad=b"k")
    assert (tmp_path / "out").read_bytes() == b"x" * 100_000
    with pytest.raises(vpqc.DecryptionError):
        vpqc.decrypt_file(old.secret, v2, tmp_path / "o2", aad=b"k")
    # Not a recipient: cannot re-wrap.
    with pytest.raises(vpqc.DecryptionError):
        vpqc.rewrap_file(vpqc.generate_encryption_keypair().secret, new.public, v1, tmp_path / "v3", aad=b"k")
    # A plain single-recipient file cannot be re-wrapped.
    vpqc.encrypt_file(old.public, src, tmp_path / "plain", aad=b"k")
    with pytest.raises(vpqc.VpqcError):
        vpqc.rewrap_file(old.secret, new.public, tmp_path / "plain", tmp_path / "v4", aad=b"k")


def test_passphrase_protected_secret_keys(tmp_path):
    keys = vpqc.generate_signing_keypair()
    text = keys.secret.to_protected_text("mật khẩu đủ dài", memory_kib=8192)
    assert text.startswith("-----BEGIN VPQC PROTECTED SECRET KEY-----")
    assert vpqc.is_protected_secret_key(text) and not vpqc.is_protected_secret_key(keys.secret.to_text())
    sk = vpqc.SecretKey.from_protected(text, "mật khẩu đủ dài")
    assert sk == keys.secret
    with pytest.raises(vpqc.DecryptionError):
        vpqc.SecretKey.from_protected(text, "wrong")
    with pytest.raises(vpqc.InvalidInputError):
        keys.secret.to_protected_text("x", memory_kib=1024)
    with pytest.raises(vpqc.InvalidInputError):
        keys.secret.to_protected_text("")
    # load(): plain text, plain binary, protected (passphrase required).
    (tmp_path / "plain").write_text(keys.secret.to_text())
    (tmp_path / "bin").write_bytes(keys.secret.to_bytes())
    (tmp_path / "prot").write_text(text)
    assert vpqc.SecretKey.load(tmp_path / "plain") == keys.secret
    assert vpqc.SecretKey.load(tmp_path / "bin") == keys.secret
    assert vpqc.SecretKey.load(tmp_path / "prot", passphrase=b"m\xe1\xba\xadt kh\xe1\xba\xa9u \xc4\x91\xe1\xbb\xa7 d\xc3\xa0i") == keys.secret
    with pytest.raises(vpqc.InvalidInputError):
        vpqc.SecretKey.load(tmp_path / "prot")


def test_protected_keys_interoperate_with_cli(tmp_path):
    import os
    import shutil
    import subprocess

    cli = os.environ.get("VPQC_CLI") or shutil.which("vpqc")
    if not cli:
        pytest.skip("vpqc CLI not available (set VPQC_CLI)")
    env = dict(os.environ, VPQC_PASSPHRASE="shared passphrase 2026")
    env.pop("VPQC_PASSPHRASE_FILE", None)
    # CLI generates a protected key; Python loads it.
    subprocess.run([cli, "keygen", "--purpose", "encrypt", "--out", str(tmp_path / "c"), "--passphrase",
                    "--kdf-memory", "8"], check=True, env=env, capture_output=True)
    sk = vpqc.SecretKey.load(tmp_path / "c.vpqc-secret", passphrase="shared passphrase 2026")
    pk = vpqc.PublicKey.from_text((tmp_path / "c.pub").read_text())
    assert vpqc.unseal(sk, vpqc.seal(pk, b"x")) == b"x"
    # Python protects a key; the CLI uses it.
    keys = vpqc.generate_encryption_keypair()
    (tmp_path / "p.key").write_text(keys.secret.to_protected_text("shared passphrase 2026", memory_kib=8192))
    (tmp_path / "p.sealed").write_bytes(vpqc.seal(keys.public, b"from python"))
    res = subprocess.run([cli, "open", "--key", str(tmp_path / "p.key"), str(tmp_path / "p.sealed")],
                         check=True, capture_output=True, env=env)
    assert res.stdout == b"from python"
