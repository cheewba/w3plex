"""Reusable byte encryption and key derivation, independent of storage formats.

Keys and plaintext are ordinary bytes. Trusted callers control their lifetime;
use memory.LockedBuffer for retained keys. Nothing here changes process or file I/O.
"""

import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Self

from ..constants import GCM_NONCE_BYTES, GCM_TAG_BYTES
from ..errors import InvalidStore
from .primitives import (
    DEFAULT_KDF,
    KdfSettings,
    decode_bytes,
    decrypt as decrypt_aead,
    derive_password_key,
    derive_subkey,
    encode_bytes,
    encrypt as encrypt_aead,
    generate_key,
    generate_salt,
)

__all__ = [
    "DEFAULT_KDF",
    "EncryptedBlock",
    "KdfSettings",
    "decrypt_aead",
    "derive_password_key",
    "derive_subkey",
    "encrypt_aead",
    "generate_key",
    "generate_salt",
    "seal",
    "unseal",
]


@dataclass(frozen=True, repr=False)
class EncryptedBlock:
    """AES-256-GCM nonce and ciphertext, including its authentication tag."""

    nonce: bytes
    ciphertext: bytes

    def __post_init__(self):
        if (
            type(self.nonce) is not bytes
            or len(self.nonce) != GCM_NONCE_BYTES
            or type(self.ciphertext) is not bytes
            or len(self.ciphertext) < GCM_TAG_BYTES
        ):
            raise InvalidStore()

    def to_data(self) -> dict[str, str]:
        """Return base64 fields suitable for a caller's JSON or YAML document."""
        return {
            "nonce": encode_bytes(self.nonce),
            "ciphertext": encode_bytes(self.ciphertext),
        }

    @classmethod
    def from_data(cls, data: Mapping[str, str]) -> Self:
        """Restore a block; unseal() must still authenticate it before use."""
        if not isinstance(data, Mapping) or set(data) != {"nonce", "ciphertext"}:
            raise InvalidStore()
        return cls(
            decode_bytes(data["nonce"], size=GCM_NONCE_BYTES),
            decode_bytes(data["ciphertext"]),
        )


def seal(data: bytes, *, key: bytes, context: bytes) -> EncryptedBlock:
    """Encrypt bytes with a fresh random nonce and authenticated public context."""
    nonce = secrets.token_bytes(GCM_NONCE_BYTES)
    return EncryptedBlock(nonce, encrypt_aead(key, nonce, data, context))


def unseal(block: EncryptedBlock, *, key: bytes, context: bytes) -> bytes:
    """Authenticate the entire block and context before returning plaintext."""
    return decrypt_aead(key, block.nonce, block.ciphertext, context)
