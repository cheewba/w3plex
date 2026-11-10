"""Common header encoding and Argon2id/AES-256-GCM helpers."""

import base64
import json
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from .errors import AuthenticationFailed, InvalidStore, UnsupportedProtection


@dataclass(frozen=True)
class KdfSettings:
    """Argon2id settings checked before creating an encryption key.

    Args:
        memory_kib: Memory requested in KiB, from 65536 to 262144.
        iterations: Number of passes over memory, from 3 to 10.
        lanes: Number of parallel lanes, from 1 to 8.
    """

    memory_kib: int = 65536
    iterations: int = 3
    lanes: int = 4

    def validate(self):
        """Check that Argon2id settings are within the supported limits.

        Returns:
            None.
        """
        if not all(
            type(value) is int
            for value in (self.memory_kib, self.iterations, self.lanes)
        ) or not (
            65536 <= self.memory_kib <= 262144
            and 3 <= self.iterations <= 10
            and 1 <= self.lanes <= 8
        ):
            raise InvalidStore()


DEFAULT_KDF = KdfSettings()


def canonical(value: Any) -> bytes:
    """Write JSON in a stable byte format.

    Args:
        value: A JSON value to encode. Objects use sorted keys and no extra spaces.

    Returns:
        JSON bytes encoded as ASCII.
    """
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def unique_fields(pairs):
    """Build a JSON object and reject repeated field names.

    Args:
        pairs: Field names and values supplied by the JSON reader.

    Returns:
        A dictionary containing the fields.
    """
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate field")
        result[key] = value
    return result


def reject_json_constant(value: str):
    """Reject JSON constants such as NaN and Infinity.

    Args:
        value: The constant found by the JSON reader.

    Returns:
        No value. This function always raises ValueError.
    """
    raise ValueError("Invalid JSON constant")


def encode_bytes(value: bytes) -> str:
    """Encode bytes as base64 text.

    Args:
        value: Bytes to encode for storage in a header.

    Returns:
        Standard base64 text.
    """
    return base64.b64encode(value).decode("ascii")


def decode_bytes(value: Any, *, size: int | None = None) -> bytes:
    """Decode base64 text and check its length when requested.

    Args:
        value: Base64 text to decode.
        size: Required number of decoded bytes. None allows any length.

    Returns:
        The decoded bytes.
    """
    success = False
    decoded = b""
    try:
        if isinstance(value, str):
            decoded = base64.b64decode(value, validate=True)
            success = size is None or len(decoded) == size
    except (ValueError, UnicodeError):
        pass
    if not success:
        raise InvalidStore()
    return decoded


def derive_key(password: bytes, header: dict[str, Any]) -> bytes:
    """Create a key from a password using the header settings.

    Args:
        password: Password bytes used by Argon2id.
        header: Header containing the salt and validated KDF settings.

    Returns:
        A 32-byte key used to protect the data key.
    """
    if not isinstance(password, bytes) or not 1 <= len(password) <= 4096:
        raise AuthenticationFailed()
    settings = header["kdf"]
    KdfSettings(
        settings["memory_kib"], settings["iterations"], settings["lanes"]
    ).validate()
    derived = None
    try:
        derived = Argon2id(
            salt=decode_bytes(header["salt"], size=16),
            length=32,
            iterations=settings["iterations"],
            lanes=settings["lanes"],
            memory_cost=settings["memory_kib"],
        ).derive(password)
    except UnsupportedAlgorithm:
        pass
    if derived is None:
        raise UnsupportedProtection()
    return derived


def decrypt(key: bytes, nonce: bytes, data: bytes, aad: bytes) -> bytes:
    """Check and decrypt AES-256-GCM data.

    Args:
        key: The 32-byte encryption key.
        nonce: The 12-byte nonce used when the data was encrypted.
        data: Encrypted bytes, including the authentication tag.
        aad: Extra data that must match the value used during encryption.

    Returns:
        The decrypted bytes. Invalid data raises an error.
    """
    if type(key) is not bytes or len(key) != 32 or len(nonce) != 12:
        raise InvalidStore()
    plaintext = None
    unsupported = False
    try:
        plaintext = AESGCM(key).decrypt(nonce, data, aad)
    except InvalidTag:
        pass
    except UnsupportedAlgorithm:
        unsupported = True
    if unsupported:
        raise UnsupportedProtection()
    if plaintext is None:
        raise AuthenticationFailed()
    return plaintext


def encrypt(key: bytes, nonce: bytes, data: bytes, aad: bytes) -> bytes:
    """Encrypt bytes with AES-256-GCM.

    Args:
        key: The 32-byte encryption key.
        nonce: A 12-byte nonce that has not been used with this key.
        data: Bytes to encrypt.
        aad: Extra data to check during decryption. It is not encrypted.

    Returns:
        Encrypted bytes followed by their authentication tag.
    """
    if type(key) is not bytes or len(key) != 32 or len(nonce) != 12:
        raise InvalidStore()
    ciphertext = None
    try:
        ciphertext = AESGCM(key).encrypt(nonce, data, aad)
    except UnsupportedAlgorithm:
        pass
    if ciphertext is None:
        raise UnsupportedProtection()
    return ciphertext
