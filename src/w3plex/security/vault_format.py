"""Version 1 vault codec; never uses or changes the legacy ENC1/KS01 format."""

import base64
import json
import secrets
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from .errors import AuthenticationFailed, InvalidStore, UnsupportedProtection

MAGIC = b"W3VAULT1\n"
MAXIMUM_SIZE = 8 * 1024 * 1024


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


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate field")
        result[key] = value
    return result


def _invalid_constant(value: str):
    raise ValueError("Invalid JSON constant")


def _encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _decode(value: Any, *, size: int | None = None) -> bytes:
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


@dataclass(frozen=True, repr=False)
class Envelope:
    header: dict[str, Any]
    wrapped_key: bytes
    payload: bytes

    def __repr__(self):
        return "Envelope(<private>)"

    def serialize(self) -> bytes:
        data = MAGIC + canonical(
            {
                "header": self.header,
                "wrapped_key": _encode(self.wrapped_key),
                "payload": _encode(self.payload),
            }
        )
        if len(data) > MAXIMUM_SIZE:
            raise InvalidStore()
        return data


def parse(data: bytes) -> Envelope:
    if (
        not isinstance(data, bytes)
        or not data.startswith(MAGIC)
        or len(data) > MAXIMUM_SIZE
    ):
        raise InvalidStore()
    document = None
    try:
        document = json.loads(
            data[len(MAGIC) :],
            object_pairs_hook=_unique,
            parse_constant=_invalid_constant,
        )
    except (ValueError, UnicodeError, RecursionError):
        pass
    if not isinstance(document, dict) or set(document) != {
        "header",
        "wrapped_key",
        "payload",
    }:
        raise InvalidStore()
    header = document["header"]
    fields = {
        "version",
        "cipher",
        "kdf",
        "salt",
        "store_id",
        "context",
        "wrap_nonce",
        "data_nonce",
    }
    if (
        not isinstance(header, dict)
        or set(header) != fields
        or len(canonical(header)) > 4096
    ):
        raise InvalidStore()
    if (
        type(header["version"]) is not int
        or header["version"] != 1
        or header["cipher"] != "AES-256-GCM"
        or header["context"] != "w3plex.vault"
    ):
        raise InvalidStore()
    identifier = header["store_id"]
    if (
        not isinstance(identifier, str)
        or len(identifier) != 32
        or any(c not in "0123456789abcdef" for c in identifier)
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
    _decode(header["salt"], size=16)
    wrapping_nonce = _decode(header["wrap_nonce"], size=12)
    data_nonce = _decode(header["data_nonce"], size=12)
    if wrapping_nonce == data_nonce:
        raise InvalidStore()
    wrapped_key = _decode(document["wrapped_key"], size=48)
    payload = _decode(document["payload"])
    if len(payload) < 16:
        raise InvalidStore()
    return Envelope(header, wrapped_key, payload)


def _derive(password: bytes, header: dict[str, Any]) -> bytes:
    if not isinstance(password, bytes) or not 1 <= len(password) <= 4096:
        raise AuthenticationFailed()
    settings = header["kdf"]
    derived = None
    try:
        derived = Argon2id(
            salt=_decode(header["salt"], size=16),
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


def _decrypt(key: bytes, nonce: bytes, data: bytes, aad: bytes) -> bytes:
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


def _encrypt(key: bytes, nonce: bytes, data: bytes, aad: bytes) -> bytes:
    ciphertext = None
    try:
        ciphertext = AESGCM(key).encrypt(nonce, data, aad)
    except UnsupportedAlgorithm:
        pass
    if ciphertext is None:
        raise UnsupportedProtection()
    return ciphertext


def unwrap(envelope: Envelope, password: bytes) -> bytes:
    key = _derive(password, envelope.header)
    return _decrypt(
        key,
        _decode(envelope.header["wrap_nonce"], size=12),
        envelope.wrapped_key,
        _wrapping_aad(envelope.header),
    )


def _wrapping_aad(header: dict[str, Any]) -> bytes:
    # Payload nonce changes during an unlocked session. It is authenticated by
    # payload AEAD, while all stable header fields authenticate the wrapped key.
    return canonical({k: v for k, v in header.items() if k != "data_nonce"}) + b"\0wrap"


def open_payload(envelope: Envelope, data_key: bytes) -> bytes:
    return _decrypt(
        data_key,
        _decode(envelope.header["data_nonce"], size=12),
        envelope.payload,
        canonical(envelope.header) + b"\0records\0" + envelope.wrapped_key,
    )


def seal(
    plaintext: bytes,
    password: bytes,
    *,
    data_key: bytes | None = None,
    settings: KdfSettings = DEFAULT_KDF,
    store_id: str | None = None,
) -> tuple[Envelope, bytes]:
    settings.validate()
    key = secrets.token_bytes(32) if data_key is None else data_key
    if len(key) != 32 or len(plaintext) > MAXIMUM_SIZE // 2:
        raise InvalidStore()
    wrapping_nonce, data_nonce = secrets.token_bytes(12), secrets.token_bytes(12)
    if wrapping_nonce == data_nonce:
        # Refuse a broken RNG rather than reuse the pair.
        raise UnsupportedProtection()
    header = {
        "version": 1,
        "cipher": "AES-256-GCM",
        "context": "w3plex.vault",
        "store_id": store_id or secrets.token_hex(16),
        "salt": _encode(secrets.token_bytes(16)),
        "wrap_nonce": _encode(wrapping_nonce),
        "data_nonce": _encode(data_nonce),
        "kdf": {
            "name": "argon2id",
            "memory_kib": settings.memory_kib,
            "iterations": settings.iterations,
            "lanes": settings.lanes,
        },
    }
    aad = canonical(header)
    wrapping_key = _derive(password, header)
    wrapped = _encrypt(wrapping_key, wrapping_nonce, key, _wrapping_aad(header))
    payload = _encrypt(key, data_nonce, plaintext, aad + b"\0records\0" + wrapped)
    envelope = Envelope(header, wrapped, payload)
    # Apply the same bounded format validation to newly written files.
    parse(envelope.serialize())
    return envelope, key


def update_payload(envelope: Envelope, data_key: bytes, plaintext: bytes) -> Envelope:
    """Update records without retaining the password or wrapping key."""
    if len(data_key) != 32 or len(plaintext) > MAXIMUM_SIZE // 2:
        raise InvalidStore()
    header = dict(envelope.header)
    nonce = secrets.token_bytes(12)
    if nonce in {
        _decode(header["data_nonce"], size=12),
        _decode(header["wrap_nonce"], size=12),
    }:
        raise UnsupportedProtection()
    header["data_nonce"] = _encode(nonce)
    encrypted = _encrypt(
        data_key,
        nonce,
        plaintext,
        canonical(header) + b"\0records\0" + envelope.wrapped_key,
    )
    result = Envelope(header, envelope.wrapped_key, encrypted)
    parse(result.serialize())
    return result
