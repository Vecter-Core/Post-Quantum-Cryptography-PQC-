"""Exception types. The native extension raises these."""


class VpqcError(Exception):
    """Base class for all vpqc errors."""


class DecryptionError(VpqcError):
    """Decryption failed: wrong key, wrong ``aad``, or the data was modified."""


class VerificationError(VpqcError):
    """A signature is not valid for this key, message and context."""


class InvalidInputError(VpqcError, ValueError):
    """A key, envelope or argument is malformed or of the wrong kind."""


class BackendError(VpqcError):
    """The random number generator or a cryptographic backend failed."""
