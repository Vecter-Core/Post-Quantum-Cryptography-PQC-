"""Post-quantum cryptography with safe defaults.

Pre-release and unaudited: do not protect real secrets with it yet.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from typing import Dict, List, Sequence, Tuple, Union

from . import _vpqc
from .errors import (
    BackendError,
    DecryptionError,
    InvalidInputError,
    VerificationError,
    VpqcError,
)

__version__ = _vpqc.NATIVE_VERSION

__all__ = [
    "PublicKey",
    "SecretKey",
    "KeyPair",
    "generate_encryption_keypair",
    "generate_signing_keypair",
    "seal",
    "unseal",
    "sign",
    "verify",
    "is_valid",
    "encrypt_file",
    "decrypt_file",
    "rewrap_file",
    "StreamEncryptor",
    "StreamDecryptor",
    "profiles",
    "is_protected_secret_key",
    "VpqcError",
    "DecryptionError",
    "VerificationError",
    "InvalidInputError",
    "BackendError",
]

BytesLike = Union[bytes, bytearray, memoryview]


def _b(value: BytesLike) -> bytes:
    return bytes(value)


@dataclass(frozen=True)
class PublicKey:
    """A public key (encryption or verification). Safe to share."""

    data: bytes

    def __post_init__(self) -> None:
        _vpqc.describe_key(self.data)  # validates the encoding

    @property
    def algorithm(self) -> str:
        """Human-readable algorithm name."""
        return _vpqc.describe_key(self.data)["algorithm"]

    def to_bytes(self) -> bytes:
        """Binary encoding."""
        return self.data

    def to_text(self) -> str:
        """Armored text encoding (``-----BEGIN VPQC PUBLIC KEY-----``)."""
        return _vpqc.public_key_to_text(self.data)

    @classmethod
    def from_bytes(cls, data: BytesLike) -> "PublicKey":
        return cls(_b(data))

    @classmethod
    def from_text(cls, text: str) -> "PublicKey":
        return cls(_vpqc.public_key_from_text(text))


@dataclass(frozen=True)
class SecretKey:
    """A secret key (decryption or signing). Keep it private.

    Python cannot guarantee memory zeroization: prefer short-lived processes or an OS
    keystore for long-term secrets.
    """

    data: bytes

    def __post_init__(self) -> None:
        _vpqc.describe_key(self.data)

    def __repr__(self) -> str:
        return f"SecretKey(<redacted {self.algorithm}>)"

    __str__ = __repr__

    @property
    def algorithm(self) -> str:
        """Human-readable algorithm name."""
        return _vpqc.describe_key(self.data)["algorithm"]

    def to_bytes(self) -> bytes:
        """Binary encoding. Unencrypted."""
        return self.data

    def to_text(self) -> str:
        """Armored text encoding. Unencrypted."""
        return _vpqc.secret_key_to_text(self.data)

    @classmethod
    def from_bytes(cls, data: BytesLike) -> "SecretKey":
        return cls(_b(data))

    @classmethod
    def from_text(cls, text: str) -> "SecretKey":
        return cls(_vpqc.secret_key_from_text(text))

    def to_protected_text(self, passphrase: Union[str, BytesLike], *, memory_kib: int = 65536) -> str:
        """Armored text encrypted under ``passphrase`` (Argon2id, XChaCha20-Poly1305; ADR-0013).

        Readable by ``SecretKey.from_protected``, by every vpqc binding and by the ``vpqc`` CLI.
        ``memory_kib`` is the Argon2id memory (8192 to 1048576; default 64 MiB).
        """
        return _vpqc.protect_secret_key(self.data, _passphrase(passphrase), memory_kib)

    @classmethod
    def from_protected(cls, data: Union[str, BytesLike], passphrase: Union[str, BytesLike]) -> "SecretKey":
        """Decrypt a passphrase-protected key (armored text or binary).

        Raises ``DecryptionError`` for a wrong passphrase or a modified key.
        """
        raw = data.encode() if isinstance(data, str) else _b(data)
        return cls(_vpqc.unprotect_secret_key(raw, _passphrase(passphrase)))

    @classmethod
    def load(cls, path: "os.PathLike[str] | str", *, passphrase: Union[str, BytesLike, None] = None) -> "SecretKey":
        """Read a key file written by the CLI or ``to_text``/``to_protected_text``: armored or
        binary, plain or passphrase-protected (then ``passphrase`` is required)."""
        with open(path, "rb") as f:
            data = f.read()
        if _vpqc.is_protected_secret_key(data):
            if passphrase is None:
                raise InvalidInputError(f"{os.fspath(path)} is protected: a passphrase is required")
            return cls.from_protected(data, passphrase)
        if data.lstrip().startswith(b"-----BEGIN"):
            return cls.from_text(data.decode())
        return cls.from_bytes(data)


def _passphrase(p: Union[str, BytesLike]) -> bytes:
    return p.encode() if isinstance(p, str) else _b(p)


def is_protected_secret_key(data: Union[str, BytesLike]) -> bool:
    """Is ``data`` a protected secret key (armored text or binary)?"""
    return _vpqc.is_protected_secret_key(data.encode() if isinstance(data, str) else _b(data))


@dataclass(frozen=True)
class KeyPair:
    """A freshly generated key pair."""

    public: PublicKey
    secret: SecretKey


def generate_encryption_keypair(profile: str = "standard") -> KeyPair:
    """Generate a key pair for :func:`seal` / :func:`unseal`."""
    public, secret = _vpqc.generate_encryption_keypair(profile)
    return KeyPair(PublicKey(public), SecretKey(secret))


def generate_signing_keypair(profile: str = "standard") -> KeyPair:
    """Generate a key pair for :func:`sign` / :func:`verify`."""
    public, secret = _vpqc.generate_signing_keypair(profile)
    return KeyPair(PublicKey(public), SecretKey(secret))


def seal(public_key: PublicKey, plaintext: BytesLike, *, aad: BytesLike = b"") -> bytes:
    """Encrypt ``plaintext`` to ``public_key``.

    ``aad`` is authenticated context that must be supplied again to :func:`unseal`.
    """
    return _vpqc.seal(public_key.data, _b(plaintext), _b(aad))


def unseal(secret_key: SecretKey, sealed: BytesLike, *, aad: BytesLike = b"") -> bytes:
    """Decrypt data produced by :func:`seal`. Raises :class:`DecryptionError` on failure."""
    return _vpqc.unseal(secret_key.data, _b(sealed), _b(aad))


def sign(secret_key: SecretKey, message: BytesLike, *, context: BytesLike) -> bytes:
    """Sign ``message``. ``context`` (at most 255 bytes) is mandatory domain separation,
    for example ``b"my-app/release-v1"``."""
    return _vpqc.sign(secret_key.data, _b(message), _b(context))


def verify(
    public_key: PublicKey, message: BytesLike, signature: BytesLike, *, context: BytesLike
) -> None:
    """Verify a signature. Returns ``None``; raises :class:`VerificationError` if invalid."""
    _vpqc.verify(public_key.data, _b(message), _b(context), _b(signature))


def is_valid(
    public_key: PublicKey, message: BytesLike, signature: BytesLike, *, context: BytesLike
) -> bool:
    """Like :func:`verify` but returns a bool for a bad signature.

    Malformed keys still raise :class:`InvalidInputError`."""
    try:
        verify(public_key, message, signature, context=context)
    except VerificationError:
        return False
    return True


PathLike = Union[str, "os.PathLike[str]"]


def _recipients(public_key: Union["PublicKey", Sequence["PublicKey"]]) -> List[bytes]:
    keys = [public_key] if isinstance(public_key, PublicKey) else list(public_key)
    if not keys or not all(isinstance(k, PublicKey) for k in keys):
        raise TypeError("expected a PublicKey or a non-empty sequence of PublicKey")
    return [k.data for k in keys]


def encrypt_file(
    public_key: Union["PublicKey", Sequence["PublicKey"]],
    input_path: PathLike,
    output_path: PathLike,
    *,
    aad: BytesLike = b"",
    envelope: bool = False,
) -> int:
    """Encrypt a file of any size in constant memory (streaming format, ADR-0007).

    Pass a list of public keys to encrypt for several recipients (up to 32, e.g. a user key
    and a recovery key); each can decrypt with their own secret key (ADR-0009). With
    ``envelope=True`` a single recipient also gets that format, so the recipients can later be
    changed with :func:`rewrap_file` (key rotation).
    The output file is replaced atomically. Returns the number of plaintext bytes.
    Raises ``OSError`` for file errors.
    """
    return _vpqc.encrypt_file(
        _recipients(public_key), _b(aad), os.fspath(input_path), os.fspath(output_path), envelope
    )


def rewrap_file(
    secret_key: SecretKey,
    public_key: Union["PublicKey", Sequence["PublicKey"]],
    input_path: PathLike,
    output_path: PathLike,
    *,
    aad: BytesLike = b"",
) -> int:
    """Change the recipients of a multi-recipient file without re-encrypting its data.

    ``secret_key`` must belong to a current recipient; the output is readable by exactly the
    new recipients. Removing someone does not revoke what they already decrypted: re-encrypt
    to revoke. Returns the number of body bytes copied.
    """
    return _vpqc.rewrap_file(
        secret_key.data, _recipients(public_key), _b(aad), os.fspath(input_path), os.fspath(output_path)
    )


def decrypt_file(
    secret_key: SecretKey, input_path: PathLike, output_path: PathLike, *, aad: BytesLike = b""
) -> int:
    """Decrypt a file produced by :func:`encrypt_file`.

    The output file appears (mode 0600 on Unix) only if the whole stream verifies; on
    :class:`DecryptionError` nothing is written. Returns the number of plaintext bytes.
    """
    return _vpqc.decrypt_file(secret_key.data, _b(aad), os.fspath(input_path), os.fspath(output_path))


class StreamEncryptor:
    """Incremental encryption for data that arrives in pieces (sockets, uploads, pipes).

    ``update()`` returns ciphertext to append (the first call includes the header);
    ``finalize()`` returns the last piece. The result is readable by :func:`decrypt_file`.
    """

    def __init__(self, public_key: Union["PublicKey", Sequence["PublicKey"]], *, aad: BytesLike = b"") -> None:
        self._inner = _vpqc.StreamEncryptor(_recipients(public_key), _b(aad))

    def update(self, data: BytesLike) -> bytes:
        return self._inner.update(_b(data))

    def finalize(self) -> bytes:
        return self._inner.finalize()


class StreamDecryptor:
    """Incremental decryption. Plaintext returned by ``update()`` must be discarded if a later
    call raises; only a successful ``finalize()`` proves the stream is complete and intact."""

    def __init__(self, secret_key: SecretKey, *, aad: BytesLike = b"") -> None:
        self._inner = _vpqc.StreamDecryptor(secret_key.data, _b(aad))

    def update(self, data: BytesLike) -> bytes:
        return self._inner.update(_b(data))

    def finalize(self) -> bytes:
        return self._inner.finalize()


def profiles() -> List[Dict[str, str]]:
    """Available profiles and the algorithms they select."""
    return [
        {"name": n, "encryption": k, "signature": s} for n, k, s in _vpqc.profiles()
    ]
