"""Shared bounded header encoding and Argon2id/AES-256-GCM primitives."""

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
    memory_kib: int = 65536
    iterations: int = 3
    lanes: int = 4

    def validate(self):
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
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def unique_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate field")
        result[key] = value
    return result


def reject_json_constant(value: str):
    raise ValueError("Invalid JSON constant")


def encode_bytes(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def decode_bytes(value: Any, *, size: int | None = None) -> bytes:
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
