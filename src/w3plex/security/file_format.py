"""Format for encrypted files, separate from vaults with several records."""

import json
import secrets
from dataclasses import dataclass
from typing import Any

from ._crypto import (
    DEFAULT_KDF,
    KdfSettings,
    canonical,
    decode_bytes,
    decrypt,
    derive_key,
    encode_bytes,
    encrypt,
    reject_json_constant,
    unique_fields,
)
from .errors import InvalidStore, UnsupportedProtection

MAGIC = b"W3FILE1\n"
MAXIMUM_PLAINTEXT = 64 * 1024 * 1024
MAXIMUM_HEADER = 4096
MAXIMUM_SIZE = len(MAGIC) + 4 + MAXIMUM_HEADER + 48 + MAXIMUM_PLAINTEXT + 16


@dataclass(frozen=True, repr=False)
class FileEnvelope:
    """Keep a W3FILE1 header and its encrypted content.

    Args:
        header: Format settings, salts, nonces and the file ID.
        wrapped_key: Data key encrypted with the password key, including its tag.
        payload: Encrypted file bytes, including their authentication tag.
    """

    header: dict[str, Any]
    wrapped_key: bytes
    payload: bytes

    def __repr__(self) -> str:
        return "FileEnvelope(<private>)"

    def serialize(self) -> bytes:
        """Encode the header and encrypted file content in W3FILE1 format.

        Returns:
            The complete container bytes, within the format size limit.
        """
        header = canonical(self.header)
        if not 1 <= len(header) <= MAXIMUM_HEADER:
            raise InvalidStore()
        raw = (
            MAGIC
            + len(header).to_bytes(4, "big")
            + header
            + self.wrapped_key
            + self.payload
        )
        if len(raw) > MAXIMUM_SIZE:
            raise InvalidStore()
        return raw


def parse(raw: bytes) -> FileEnvelope:
    """Check a W3FILE1 file without decrypting it.

    This checks the file layout and work limits. Decryption must still check the
    authentication tags.

    Args:
        raw: Complete container bytes to parse.

    Returns:
        A FileEnvelope with the checked header and encrypted data.
    """
    if (
        type(raw) is not bytes
        or len(raw) > MAXIMUM_SIZE
        or len(raw) < len(MAGIC) + 4
        or not raw.startswith(MAGIC)
    ):
        raise InvalidStore()
    start = len(MAGIC) + 4
    size = int.from_bytes(raw[len(MAGIC) : start], "big")
    if not 1 <= size <= MAXIMUM_HEADER or len(raw) < start + size + 48 + 16:
        raise InvalidStore()
    header = None
    try:
        header = json.loads(
            raw[start : start + size],
            object_pairs_hook=unique_fields,
            parse_constant=reject_json_constant,
        )
    except (ValueError, UnicodeError, RecursionError):
        pass
    if not isinstance(header, dict) or set(header) != {
        "version",
        "cipher",
        "context",
        "file_id",
        "kdf",
        "salt",
        "wrap_nonce",
        "data_nonce",
    }:
        raise InvalidStore()
    if (
        type(header["version"]) is not int
        or header["version"] != 1
        or header["cipher"] != "AES-256-GCM"
        or header["context"] != "w3plex.file"
    ):
        raise InvalidStore()
    identifier = header["file_id"]
    if (
        type(identifier) is not str
        or len(identifier) != 32
        or any(char not in "0123456789abcdef" for char in identifier)
    ):
        raise InvalidStore()
    kdf = header["kdf"]
    if (
        not isinstance(kdf, dict)
        or set(kdf) != {"name", "memory_kib", "iterations", "lanes"}
        or kdf["name"] != "argon2id"
    ):
        raise InvalidStore()
    KdfSettings(kdf["memory_kib"], kdf["iterations"], kdf["lanes"]).validate()
    decode_bytes(header["salt"], size=16)
    wrap_nonce = decode_bytes(header["wrap_nonce"], size=12)
    data_nonce = decode_bytes(header["data_nonce"], size=12)
    if wrap_nonce == data_nonce:
        raise InvalidStore()
    end = start + size
    wrapped_key, payload = raw[end : end + 48], raw[end + 48 :]
    if len(payload) > MAXIMUM_PLAINTEXT + 16:
        raise InvalidStore()
    return FileEnvelope(header, wrapped_key, payload)


def unwrap(envelope: FileEnvelope, password: bytes) -> bytes:
    """Use the password to decrypt the data key.

    Args:
        envelope: A container returned by parse() or seal().
        password: Password bytes used to protect the data key.

    Returns:
        The 32-byte data key.
    """
    return decrypt(
        derive_key(password, envelope.header),
        decode_bytes(envelope.header["wrap_nonce"], size=12),
        envelope.wrapped_key,
        MAGIC + b"\0key\0" + canonical(envelope.header),
    )


def open_payload(envelope: FileEnvelope, key: bytes) -> bytes:
    """Check and decrypt the file content.

    Args:
        envelope: A container returned by parse() or seal().
        key: The 32-byte key returned by unwrap() or seal().

    Returns:
        The decrypted bytes. Failed authentication raises an error.
    """
    return decrypt(
        key,
        decode_bytes(envelope.header["data_nonce"], size=12),
        envelope.payload,
        MAGIC + b"\0file\0" + canonical(envelope.header) + envelope.wrapped_key,
    )


def seal(
    plaintext: bytes,
    password: bytes,
    *,
    settings: KdfSettings = DEFAULT_KDF,
) -> tuple[FileEnvelope, bytes]:
    """Encrypt file content with a new key, salt and nonces.

    Args:
        plaintext: Bytes to encrypt, within the file size limit.
        password: Password bytes used to protect the new data key.
        settings: Argon2id settings that control the time and memory used to derive a
            key.

    Returns:
        A pair containing the FileEnvelope and its 32-byte data key.
    """
    settings.validate()
    if type(plaintext) is not bytes or len(plaintext) > MAXIMUM_PLAINTEXT:
        raise InvalidStore()
    key = secrets.token_bytes(32)
    wrapping_nonce, data_nonce = secrets.token_bytes(12), secrets.token_bytes(12)
    if wrapping_nonce == data_nonce:
        raise UnsupportedProtection()
    header = {
        "version": 1,
        "cipher": "AES-256-GCM",
        "context": "w3plex.file",
        "file_id": secrets.token_hex(16),
        "kdf": {
            "name": "argon2id",
            "memory_kib": settings.memory_kib,
            "iterations": settings.iterations,
            "lanes": settings.lanes,
        },
        "salt": encode_bytes(secrets.token_bytes(16)),
        "wrap_nonce": encode_bytes(wrapping_nonce),
        "data_nonce": encode_bytes(data_nonce),
    }
    encoded = canonical(header)
    wrapped = encrypt(
        derive_key(password, header), wrapping_nonce, key, MAGIC + b"\0key\0" + encoded
    )
    payload = encrypt(
        key, data_nonce, plaintext, MAGIC + b"\0file\0" + encoded + wrapped
    )
    envelope = FileEnvelope(header, wrapped, payload)
    return envelope, key
