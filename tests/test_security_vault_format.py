"""Fixed V1 format fixtures and bounded parsing before password derivation."""

import base64
import hashlib
import json
from pathlib import Path

import pytest

from w3plex.security import vault_format as codec
from w3plex.security.errors import AuthenticationFailed, InvalidStore

FIXTURES = Path(__file__).parent / "fixtures/vault-v1"


def document():
    raw = (FIXTURES / "sample.vault").read_bytes()
    return json.loads(raw[len(codec.MAGIC) :])


def test_fixed_v1_ciphertext_is_readable_and_byte_stable():
    manifest = json.loads((FIXTURES / "manifest.json").read_text())
    raw = (FIXTURES / "sample.vault").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == manifest["sha256"]["sample.vault"]
    envelope = codec.parse(raw)
    assert envelope.serialize() == raw
    key = codec.unwrap(envelope, manifest["password"].encode())
    assert key.hex() == manifest["data_key_hex"]
    assert codec.open_payload(envelope, key).hex() == manifest["plaintext_hex"]


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
def test_fixed_v1_header_and_data_changes_are_detected(field):
    value = document()
    if field in {"wrapped_key", "payload"}:
        decoded = bytearray(base64.b64decode(value[field]))
        decoded[-1] ^= 1
        value[field] = base64.b64encode(decoded).decode()
    elif field in {"salt", "wrap_nonce", "data_nonce"}:
        decoded = bytearray(base64.b64decode(value["header"][field]))
        decoded[-1] ^= 1
        value["header"][field] = base64.b64encode(decoded).decode()
    elif field == "kdf":
        value["header"][field]["iterations"] += 1
    elif field == "version":
        value["header"][field] = 2
    elif field == "store_id":
        value["header"][field] = "ff" * 16
    else:
        value["header"][field] = "unsupported"
    with pytest.raises((InvalidStore, AuthenticationFailed)):
        changed = codec.parse(codec.MAGIC + codec.canonical(value))
        key = codec.unwrap(changed, b"PUBLIC-TEST-v1-password")
        codec.open_payload(changed, key)


@pytest.mark.parametrize(
    "field,value",
    [
        ("memory_kib", 10**9),
        ("memory_kib", True),
        ("iterations", 10000),
        ("iterations", 2),
        ("lanes", 100),
        ("lanes", 0),
    ],
)
def test_resource_bounds_are_checked_before_kdf(monkeypatch, field, value):
    def forbidden(**kwargs):
        raise AssertionError("Invalid metadata must not start the KDF")

    monkeypatch.setattr(codec, "Argon2id", forbidden)
    changed = document()
    changed["header"]["kdf"][field] = value
    with pytest.raises(InvalidStore):
        codec.parse(codec.MAGIC + codec.canonical(changed))


@pytest.mark.parametrize(
    "raw",
    [
        b"KS01unsupported",
        codec.MAGIC + b'{"header":{},"header":{}}',
        codec.MAGIC + b"[]",
        codec.MAGIC + b"{" + b"[" * 2000,
    ],
)
def test_unsupported_duplicate_or_deep_json_is_rejected(raw):
    with pytest.raises(InvalidStore):
        codec.parse(raw)


def test_total_size_is_bounded_before_json_loading(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Oversized input must not reach JSON parsing")

    monkeypatch.setattr(codec.json, "loads", forbidden)
    with pytest.raises(InvalidStore):
        codec.parse(codec.MAGIC + bytes(codec.MAXIMUM_SIZE))


def test_nonfinite_header_value_is_invalid_store():
    value = document()
    value["header"]["kdf"]["memory_kib"] = float("nan")
    with pytest.raises(InvalidStore):
        codec.parse(codec.MAGIC + json.dumps(value).encode())
