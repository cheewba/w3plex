"""Version 1 vault codec; never uses or changes the legacy ENC1/KS01 format."""

import json
import secrets
from dataclasses import dataclass
from typing import Any

from .crypto import (
    DEFAULT_KDF as DEFAULT_KDF,  # noqa: PLC0414 -- public re-export for type checkers
    KdfSettings as KdfSettings,  # noqa: PLC0414 -- public re-export for type checkers
    canonical as canonical,  # noqa: PLC0414 -- public re-export for type checkers
    decode_bytes,
    decrypt,
    derive_key,
    encode_bytes,
    encrypt,
    reject_json_constant as reject_json_constant,  # noqa: PLC0414 -- public re-export
    unique_fields as unique_fields,  # noqa: PLC0414 -- public re-export
)
from .errors import InvalidStore, UnsupportedProtection

MAGIC = b"W3VAULT1\n"
MAXIMUM_SIZE = 8 * 1024 * 1024


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
                "wrapped_key": encode_bytes(self.wrapped_key),
                "payload": encode_bytes(self.payload),
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
            object_pairs_hook=unique_fields,
            parse_constant=reject_json_constant,
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
    decode_bytes(header["salt"], size=16)
    wrapping_nonce = decode_bytes(header["wrap_nonce"], size=12)
    data_nonce = decode_bytes(header["data_nonce"], size=12)
    if wrapping_nonce == data_nonce:
        raise InvalidStore()
    wrapped_key = decode_bytes(document["wrapped_key"], size=48)
    payload = decode_bytes(document["payload"])
    if len(payload) < 16:
        raise InvalidStore()
    return Envelope(header, wrapped_key, payload)


def unwrap(envelope: Envelope, password: bytes) -> bytes:
    key = derive_key(password, envelope.header)
    return decrypt(
        key,
        decode_bytes(envelope.header["wrap_nonce"], size=12),
        envelope.wrapped_key,
        _wrapping_aad(envelope.header),
    )


def _wrapping_aad(header: dict[str, Any]) -> bytes:
    # Payload nonce changes during an unlocked session. It is authenticated by
    # payload AEAD, while all stable header fields authenticate the wrapped key.
    return canonical({k: v for k, v in header.items() if k != "data_nonce"}) + b"\0wrap"


def open_payload(envelope: Envelope, data_key: bytes) -> bytes:
    return decrypt(
        data_key,
        decode_bytes(envelope.header["data_nonce"], size=12),
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
        "salt": encode_bytes(secrets.token_bytes(16)),
        "wrap_nonce": encode_bytes(wrapping_nonce),
        "data_nonce": encode_bytes(data_nonce),
        "kdf": {
            "name": "argon2id",
            "memory_kib": settings.memory_kib,
            "iterations": settings.iterations,
            "lanes": settings.lanes,
        },
    }
    aad = canonical(header)
    wrapping_key = derive_key(password, header)
    wrapped = encrypt(wrapping_key, wrapping_nonce, key, _wrapping_aad(header))
    payload = encrypt(key, data_nonce, plaintext, aad + b"\0records\0" + wrapped)
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
        decode_bytes(header["data_nonce"], size=12),
        decode_bytes(header["wrap_nonce"], size=12),
    }:
        raise UnsupportedProtection()
    header["data_nonce"] = encode_bytes(nonce)
    encrypted = encrypt(
        data_key,
        nonce,
        plaintext,
        canonical(header) + b"\0records\0" + envelope.wrapped_key,
    )
    result = Envelope(header, envelope.wrapped_key, encrypted)
    parse(result.serialize())
    return result
