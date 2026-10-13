"""Real Argon2id/AES-GCM; synthetic secrets and no weaker backend fallback."""

import base64
import json
from pathlib import Path

import pytest
from cryptography.exceptions import UnsupportedAlgorithm

from w3plex.security import crypto, vault_format as codec
from w3plex.security.errors import (
    AuthenticationFailed,
    InvalidStore,
    UnsupportedProtection,
)

PASSWORD = b"PUBLIC-TEST-master"
VALUE = b"PUBLIC-TEST-api-secret-751045"
FIXTURES = Path(__file__).parent / "fixtures/vault-v1"


@pytest.mark.parametrize("operation", ["encrypt", "decrypt"])
def test_missing_aes_backend_returns_safe_capability_error(monkeypatch, operation):
    envelope = codec.parse((FIXTURES / "sample.vault").read_bytes())

    def unavailable(key):
        raise UnsupportedAlgorithm("PUBLIC-TEST-private-backend-details")

    monkeypatch.setattr(crypto, "AESGCM", unavailable)
    with pytest.raises(UnsupportedProtection) as raised:
        if operation == "encrypt":
            codec.seal(VALUE, PASSWORD)
        else:
            codec.unwrap(envelope, b"PUBLIC-TEST-v1-password")
    assert raised.value.__cause__ is None and raised.value.__context__ is None
    assert "private" not in str(raised.value)


def test_missing_argon_at_derive_has_no_weaker_retry(monkeypatch):
    calls = []

    class Missing:
        def __init__(self, **kwargs):
            calls.append(kwargs)

        def derive(self, password):
            raise UnsupportedAlgorithm("PUBLIC-TEST-private-backend-details")

    monkeypatch.setattr(crypto, "Argon2id", Missing)
    envelope = codec.parse((FIXTURES / "sample.vault").read_bytes())
    with pytest.raises(UnsupportedProtection) as raised:
        codec.unwrap(envelope, b"PUBLIC-TEST-v1-password")
    assert len(calls) == 1
    assert (calls[0]["memory_cost"], calls[0]["iterations"], calls[0]["lanes"]) == (
        65536,
        3,
        4,
    )
    assert raised.value.__context__ is None


def test_repeated_initial_nonces_stop_before_kdf(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Repeated nonces must not start derivation")

    monkeypatch.setattr(codec.secrets, "token_bytes", lambda size: bytes(size))
    monkeypatch.setattr(crypto, "Argon2id", forbidden)
    with pytest.raises(UnsupportedProtection):
        codec.seal(VALUE, PASSWORD)


@pytest.mark.parametrize("field", ["data_nonce", "wrap_nonce"])
def test_repeated_update_nonce_is_rejected(monkeypatch, field):
    envelope = codec.parse((FIXTURES / "sample.vault").read_bytes())
    nonce = base64.b64decode(envelope.header[field])
    monkeypatch.setattr(codec.secrets, "token_bytes", lambda size: nonce)
    with pytest.raises(UnsupportedProtection):
        codec.update_payload(envelope, bytes(range(32)), VALUE)


def test_wrong_password_and_payload_integrity_return_no_plaintext():
    envelope = codec.parse((FIXTURES / "sample.vault").read_bytes())
    with pytest.raises(AuthenticationFailed) as raised:
        codec.unwrap(envelope, b"PUBLIC-TEST-wrong-password")
    assert raised.value.__context__ is None
    with pytest.raises(AuthenticationFailed):
        codec.open_payload(envelope, b"x" * 32)


def test_default_codec_roundtrip_fresh_salt_and_nonces():
    first, key = codec.seal(VALUE, PASSWORD)
    second, other_key = codec.seal(VALUE, PASSWORD)
    assert key != other_key
    assert first.header["salt"] != second.header["salt"]
    assert first.header["wrap_nonce"] != first.header["data_nonce"]
    assert first.header["kdf"] == {
        "name": "argon2id",
        "memory_kib": 65536,
        "iterations": 3,
        "lanes": 4,
    }
    loaded = codec.parse(first.serialize())
    assert codec.open_payload(loaded, codec.unwrap(loaded, PASSWORD)) == VALUE
    updated = codec.update_payload(loaded, key, b"changed")
    assert updated.header["data_nonce"] != loaded.header["data_nonce"]
    assert updated.wrapped_key == loaded.wrapped_key
    assert codec.open_payload(updated, codec.unwrap(updated, PASSWORD)) == b"changed"
    assert (
        PASSWORD not in first.serialize()
        and VALUE not in first.serialize()
        and key not in first.serialize()
    )


@pytest.mark.parametrize(
    "field",
    [
        "version",
        "cipher",
        "context",
        "store_id",
        "salt",
        "wrap_nonce",
        "data_nonce",
        "kdf",
        "wrapped_key",
        "payload",
    ],
)
def test_changed_format_fields_fail_authentication(field):
    envelope, _ = codec.seal(VALUE, PASSWORD)
    document = json.loads(envelope.serialize()[len(codec.MAGIC) :])
    if field in {"wrapped_key", "payload"}:
        raw = bytearray(base64.b64decode(document[field]))
        raw[-1] ^= 1
        document[field] = base64.b64encode(raw).decode()
    elif field == "kdf":
        document["header"]["kdf"]["iterations"] += 1
    elif field in {"salt", "wrap_nonce", "data_nonce"}:
        raw = bytearray(base64.b64decode(document["header"][field]))
        raw[-1] ^= 1
        document["header"][field] = base64.b64encode(raw).decode()
    elif field == "version":
        document["header"][field] = 2
    elif field == "store_id":
        document["header"][field] = "a" * 32
    else:
        document["header"][field] = "unsupported"
    with pytest.raises((InvalidStore, AuthenticationFailed)):
        changed = codec.parse(codec.MAGIC + codec.canonical(document))
        codec.open_payload(changed, codec.unwrap(changed, PASSWORD))


def test_work_bounds_before_kdf_and_no_missing_backend_fallback(monkeypatch):
    envelope, _ = codec.seal(VALUE, PASSWORD)
    document = json.loads(envelope.serialize()[len(codec.MAGIC) :])
    attempts = []

    def missing(**kwargs):
        attempts.append(kwargs)
        raise UnsupportedAlgorithm("PRIVATE dependency details")

    monkeypatch.setattr(crypto, "Argon2id", missing)
    for field, value in [
        ("memory_kib", 10**9),
        ("iterations", 10000),
        ("lanes", 100),
        ("memory_kib", True),
    ]:
        modified = json.loads(json.dumps(document))
        modified["header"]["kdf"][field] = value
        with pytest.raises(InvalidStore):
            codec.parse(codec.MAGIC + codec.canonical(modified))
    assert attempts == []
    with pytest.raises(UnsupportedProtection) as caught:
        codec.unwrap(envelope, PASSWORD)
    assert len(attempts) == 1
    assert caught.value.__context__ is None
    assert "PRIVATE" not in str(caught.value)


def test_store_size_and_duplicate_header_fields_rejected():
    with pytest.raises(InvalidStore):
        codec.parse(codec.MAGIC + b"x" * codec.MAXIMUM_SIZE)
    with pytest.raises(InvalidStore):
        codec.parse(codec.MAGIC + b'{"header":{},"header":{}}')
