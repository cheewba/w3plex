"""Shared Argon2id, HKDF, AES-GCM and strict envelope encoding."""

import base64
import json
import secrets
from dataclasses import dataclass
from typing import Any, Self

from cryptography.exceptions import InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ..constants import AES256_KEY_BYTES, GCM_NONCE_BYTES, KDF_SALT_BYTES
from ..errors import AuthenticationFailed, InvalidStore, UnsupportedProtection

# Minimum Argon2id memory cost, in KiB; also the default writer cost (64 MiB).
ARGON2_MIN_MEMORY_KIB = 64 * 1024
# Maximum accepted Argon2id memory-cost parameter (256 MiB).
ARGON2_MAX_MEMORY_KIB = 256 * 1024
# Minimum Argon2id pass count; also the default writer pass count.
ARGON2_MIN_ITERATIONS = 3
# Maximum accepted Argon2id pass count, bounding work on untrusted headers.
ARGON2_MAX_ITERATIONS = 10
# Argon2id requires at least one parallel lane.
ARGON2_MIN_LANES = 1
# Limit the parallelism requested by an untrusted envelope header.
ARGON2_MAX_LANES = 8
# Newly written envelopes use four Argon2id lanes.
ARGON2_DEFAULT_LANES = 4
# Bound password input before passing it to the key-derivation implementation.
MAX_PASSWORD_BYTES = 4096


@dataclass(frozen=True)
class KdfSettings:
    """Bound the memory and CPU work accepted for Argon2id."""

    memory_kib: int = ARGON2_MIN_MEMORY_KIB
    iterations: int = ARGON2_MIN_ITERATIONS
    lanes: int = ARGON2_DEFAULT_LANES

    def validate(self):
        """Reject unsupported or excessive derivation costs."""
        if not all(
            type(value) is int
            for value in (self.memory_kib, self.iterations, self.lanes)
        ) or not (
            ARGON2_MIN_MEMORY_KIB <= self.memory_kib <= ARGON2_MAX_MEMORY_KIB
            and ARGON2_MIN_ITERATIONS <= self.iterations <= ARGON2_MAX_ITERATIONS
            and ARGON2_MIN_LANES <= self.lanes <= ARGON2_MAX_LANES
        ):
            raise InvalidStore()

    def to_data(self) -> dict[str, str | int]:
        """Return public settings suitable for JSON or YAML."""
        self.validate()
        return {
            "name": "argon2id",
            "memory_kib": self.memory_kib,
            "iterations": self.iterations,
            "lanes": self.lanes,
        }

    @classmethod
    def from_data(cls, data: Any) -> Self:
        """Validate stored settings before performing expensive derivation."""
        if (
            not isinstance(data, dict)
            or set(data) != {"name", "memory_kib", "iterations", "lanes"}
            or data["name"] != "argon2id"
        ):
            raise InvalidStore()
        settings = cls(data["memory_kib"], data["iterations"], data["lanes"])
        settings.validate()
        return settings


# Default Argon2id profile for newly written file and vault envelopes.
DEFAULT_KDF = KdfSettings()


def canonical(value: Any) -> bytes:
    """Encode finite JSON with stable keys, ASCII escapes and no whitespace."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def unique_fields(pairs):
    """Decode a JSON object while rejecting duplicate field names."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate field")
        result[key] = value
    return result


def reject_json_constant(value: str):
    """Reject JSON constants such as NaN and Infinity."""
    raise ValueError("Invalid JSON constant")


def encode_bytes(value: bytes) -> str:
    """Encode bytes as standard base64 text."""
    return base64.b64encode(value).decode("ascii")


def decode_bytes(value: Any, *, size: int | None = None) -> bytes:
    """Decode strict base64 and optionally require an exact byte length."""
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


def generate_key() -> bytes:
    """Generate an AES-256 key. The caller owns and protects the returned bytes."""
    return secrets.token_bytes(AES256_KEY_BYTES)


def generate_salt() -> bytes:
    """Generate a public, random salt for a password key or subkey."""
    return secrets.token_bytes(KDF_SALT_BYTES)


def derive_password_key(
    password: bytes, *, salt: bytes, settings: KdfSettings = DEFAULT_KDF
) -> bytes:
    """Derive an AES-256 key from a password and explicit Argon2id parameters."""
    if not isinstance(password, bytes) or not 1 <= len(password) <= MAX_PASSWORD_BYTES:
        raise AuthenticationFailed()
    if type(salt) is not bytes or len(salt) < KDF_SALT_BYTES:
        raise InvalidStore()
    settings.validate()
    derived = None
    try:
        derived = Argon2id(
            salt=salt,
            length=AES256_KEY_BYTES,
            iterations=settings.iterations,
            lanes=settings.lanes,
            memory_cost=settings.memory_kib,
        ).derive(password)
    except UnsupportedAlgorithm:
        pass
    if derived is None:
        raise UnsupportedProtection()
    return derived


def derive_subkey(key: bytes, *, salt: bytes, context: bytes) -> bytes:
    """Derive a purpose-specific AES-256 key from a strong key, never a password."""
    if (
        type(key) is not bytes
        or len(key) != AES256_KEY_BYTES
        or type(salt) is not bytes
        or len(salt) < KDF_SALT_BYTES
        or type(context) is not bytes
    ):
        raise InvalidStore()
    derived = None
    try:
        derived = HKDF(
            algorithm=hashes.SHA256(), length=AES256_KEY_BYTES, salt=salt, info=context
        ).derive(key)
    except UnsupportedAlgorithm:
        pass
    if derived is None:
        raise UnsupportedProtection()
    return derived


def _validate_aead_inputs(key: bytes, nonce: bytes, data: bytes, aad: bytes) -> None:
    if (
        type(key) is not bytes
        or len(key) != AES256_KEY_BYTES
        or type(nonce) is not bytes
        or len(nonce) != GCM_NONCE_BYTES
        or type(data) is not bytes
        or type(aad) is not bytes
    ):
        raise InvalidStore()


def decrypt(key: bytes, nonce: bytes, data: bytes, aad: bytes) -> bytes:
    """Authenticate AES-256-GCM ciphertext and associated data before returning bytes."""
    _validate_aead_inputs(key, nonce, data, aad)
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
    """Encrypt with a caller-owned, never-repeated nonce; append the GCM tag."""
    _validate_aead_inputs(key, nonce, data, aad)
    ciphertext = None
    try:
        ciphertext = AESGCM(key).encrypt(nonce, data, aad)
    except UnsupportedAlgorithm:
        pass
    if ciphertext is None:
        raise UnsupportedProtection()
    return ciphertext
