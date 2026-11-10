"""Version 1 vault format. Legacy ENC1/KS01 formats are unchanged."""

import json
import secrets
from dataclasses import dataclass
from typing import Any

from ._crypto import (
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
from .constants import (
    AES256_KEY_BYTES,
    GCM_NONCE_BYTES,
    GCM_TAG_BYTES,
    IDENTIFIER_BYTES,
    IDENTIFIER_HEX_LENGTH,
    KDF_SALT_BYTES,
    WRAPPED_KEY_BYTES,
)
from .errors import InvalidStore, UnsupportedProtection

# Prefix identifying a version 1 encrypted record vault.
MAGIC = b"W3VAULT1\n"
# Maximum serialized vault size, including JSON and base64 overhead (8 MiB).
MAXIMUM_SIZE = 8 * 1024 * 1024
# Maximum canonical JSON header size, in bytes (4 KiB).
MAXIMUM_HEADER = 4096
# The numeric header version authenticated by the W3VAULT1 envelope.
_FORMAT_VERSION = 1
# Reserve half the container budget for base64 expansion and envelope fields.
_PLAINTEXT_BUDGET_DIVISOR = 2


@dataclass(frozen=True, repr=False)
class Envelope:
    """Keep a W3VAULT1 header and its encrypted records.

    Args:
        header: Format settings, salts, nonces and the store ID.
        wrapped_key: Data key encrypted with the password key, including its tag.
        payload: Encrypted record JSON, including its authentication tag.
    """

    header: dict[str, Any]
    wrapped_key: bytes
    payload: bytes

    def __repr__(self):
        return "Envelope(<private>)"

    def serialize(self) -> bytes:
        """Encode the header and encrypted record document in W3VAULT1 format.

        Returns:
            The complete container bytes, within the format size limit.
        """
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
    """Check a W3VAULT1 file without decrypting it.

    This checks the file layout and work limits. Decryption must still check the
    authentication tags.

    Args:
        data: Complete container bytes to parse.

    Returns:
        A Envelope with the checked header and encrypted data.
    """
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
        or len(canonical(header)) > MAXIMUM_HEADER
    ):
        raise InvalidStore()
    if (
        type(header["version"]) is not int
        or header["version"] != _FORMAT_VERSION
        or header["cipher"] != "AES-256-GCM"
        or header["context"] != "w3plex.vault"
    ):
        raise InvalidStore()
    identifier = header["store_id"]
    if (
        not isinstance(identifier, str)
        or len(identifier) != IDENTIFIER_HEX_LENGTH
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
    decode_bytes(header["salt"], size=KDF_SALT_BYTES)
    wrapping_nonce = decode_bytes(header["wrap_nonce"], size=GCM_NONCE_BYTES)
    data_nonce = decode_bytes(header["data_nonce"], size=GCM_NONCE_BYTES)
    if wrapping_nonce == data_nonce:
        raise InvalidStore()
    wrapped_key = decode_bytes(document["wrapped_key"], size=WRAPPED_KEY_BYTES)
    payload = decode_bytes(document["payload"])
    if len(payload) < GCM_TAG_BYTES:
        raise InvalidStore()
    return Envelope(header, wrapped_key, payload)


def unwrap(envelope: Envelope, password: bytes) -> bytes:
    """Use the password to decrypt the data key.

    Args:
        envelope: A container returned by parse() or seal().
        password: Password bytes used to protect the data key.

    Returns:
        The 32-byte data key.
    """
    key = derive_key(password, envelope.header)
    return decrypt(
        key,
        decode_bytes(envelope.header["wrap_nonce"], size=GCM_NONCE_BYTES),
        envelope.wrapped_key,
        _wrapping_aad(envelope.header),
    )


def _wrapping_aad(header: dict[str, Any]) -> bytes:
    # Payload nonce changes during an unlocked session. It is authenticated by
    # payload AEAD, while all stable header fields authenticate the wrapped key.
    return canonical({k: v for k, v in header.items() if k != "data_nonce"}) + b"\0wrap"


def open_payload(envelope: Envelope, data_key: bytes) -> bytes:
    """Check and decrypt the record document.

    Args:
        envelope: A container returned by parse() or seal().
        data_key: The 32-byte key returned by unwrap() or seal().

    Returns:
        The decrypted bytes. Failed authentication raises an error.
    """
    return decrypt(
        data_key,
        decode_bytes(envelope.header["data_nonce"], size=GCM_NONCE_BYTES),
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
    """Encrypt a record document and protect its data key.

    Args:
        plaintext: JSON record bytes to encrypt.
        password: Password bytes used to protect the data key.
        data_key: An existing 32-byte data key, or None to create a new one.
        settings: Argon2id settings that control the time and memory used to derive a
            key.
        store_id: Existing store ID to preserve, or None to create a new ID.

    Returns:
        A pair containing the Envelope and its 32-byte data key.
    """
    settings.validate()
    key = secrets.token_bytes(AES256_KEY_BYTES) if data_key is None else data_key
    if (
        len(key) != AES256_KEY_BYTES
        or len(plaintext) > MAXIMUM_SIZE // _PLAINTEXT_BUDGET_DIVISOR
    ):
        raise InvalidStore()
    if store_id and (
        len(store_id) != IDENTIFIER_HEX_LENGTH
        or any(char not in "0123456789abcdef" for char in store_id)
    ):
        raise InvalidStore()
    wrapping_nonce, data_nonce = (
        secrets.token_bytes(GCM_NONCE_BYTES),
        secrets.token_bytes(GCM_NONCE_BYTES),
    )
    if wrapping_nonce == data_nonce:
        # Refuse a broken RNG rather than reuse the pair.
        raise UnsupportedProtection()
    header = {
        "version": _FORMAT_VERSION,
        "cipher": "AES-256-GCM",
        "context": "w3plex.vault",
        "store_id": store_id or secrets.token_hex(IDENTIFIER_BYTES),
        "salt": encode_bytes(secrets.token_bytes(KDF_SALT_BYTES)),
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
    return envelope, key


def update_payload(envelope: Envelope, data_key: bytes, plaintext: bytes) -> Envelope:
    """Update encrypted records without keeping the password.

    Args:
        envelope: The current vault header and encrypted data.
        data_key: The 32-byte key for this vault.
        plaintext: New record document bytes.

    Returns:
        A new Envelope with the same password wrapper and a new payload nonce.
    """
    if (
        len(data_key) != AES256_KEY_BYTES
        or len(plaintext) > MAXIMUM_SIZE // _PLAINTEXT_BUDGET_DIVISOR
    ):
        raise InvalidStore()
    header = dict(envelope.header)
    nonce = secrets.token_bytes(GCM_NONCE_BYTES)
    if nonce in {
        decode_bytes(header["data_nonce"], size=GCM_NONCE_BYTES),
        decode_bytes(header["wrap_nonce"], size=GCM_NONCE_BYTES),
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
    return result
