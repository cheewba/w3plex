"""Modern external-file acceptance with public synthetic inputs only."""

import hashlib
import json
from pathlib import Path

import pytest
from cryptography.exceptions import UnsupportedAlgorithm

from w3plex.security import crypto, file_format as codec, vault_format
from w3plex.security.errors import (
    AuthenticationFailed,
    InvalidStore,
    UnsupportedProtection,
)

FIXTURES = Path(__file__).parent / "fixtures/file-v1"
PASSWORD = b"PUBLIC-TEST-file-v1-password"


@pytest.fixture
def fixed_file():
    manifest = json.loads((FIXTURES / "manifest.json").read_text())
    raw = (FIXTURES / "sample.enc").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == manifest["sha256"]
    return raw, manifest


def test_independent_fixed_ciphertext_restores_every_byte(fixed_file):
    raw, manifest = fixed_file
    envelope = codec.parse(raw)
    key = codec.unwrap(envelope, PASSWORD)
    assert key.hex() == manifest["file_key_hex"]
    assert codec.open_payload(envelope, key).hex() == manifest["plaintext_hex"]
    assert envelope.serialize() == raw
    assert "PUBLIC-TEST" not in repr(envelope)


@pytest.mark.parametrize(
    "plaintext", [b"", b"\x00\xff\xfe\r\n", "hello 世界\n".encode()]
)
def test_roundtrip_fresh_keys_salts_and_nonces(plaintext):
    first, key = codec.seal(plaintext, PASSWORD)
    other, other_key = codec.seal(plaintext, PASSWORD)
    assert key != other_key
    for field in ("salt", "wrap_nonce", "data_nonce", "file_id"):
        assert first.header[field] != other.header[field]
    assert first.header["wrap_nonce"] != first.header["data_nonce"]
    assert first.header["kdf"] == {
        "name": "argon2id",
        "memory_kib": 65536,
        "iterations": 3,
        "lanes": 4,
    }
    parsed = codec.parse(first.serialize())
    assert codec.open_payload(parsed, codec.unwrap(parsed, PASSWORD)) == plaintext
    assert PASSWORD not in first.serialize() and key not in first.serialize()


def test_wrong_password_and_wrong_cached_key_return_safe_errors(fixed_file):
    raw, _ = fixed_file
    envelope = codec.parse(raw)
    for action in (
        lambda: codec.unwrap(envelope, b"PUBLIC-TEST-wrong-password"),
        lambda: codec.open_payload(envelope, b"x" * 32),
    ):
        with pytest.raises(AuthenticationFailed) as raised:
            action()
        assert raised.value.__cause__ is None and raised.value.__context__ is None
        assert str(raised.value) == "authentication_failed"


@pytest.mark.parametrize(
    "field",
    [
        "version",
        "cipher",
        "context",
        "file_id",
        "kdf",
        "salt",
        "wrap_nonce",
        "data_nonce",
        "wrapped_key",
        "payload",
    ],
)
def test_every_format_field_is_authenticated(fixed_file, field):
    raw, manifest = fixed_file
    original = codec.parse(raw)
    header = json.loads(crypto.canonical(original.header))
    wrapped, payload = original.wrapped_key, original.payload
    if field == "wrapped_key":
        wrapped = wrapped[:-1] + bytes([wrapped[-1] ^ 1])
    elif field == "payload":
        payload = payload[:-1] + bytes([payload[-1] ^ 1])
    elif field in {"salt", "wrap_nonce", "data_nonce"}:
        value = crypto.decode_bytes(header[field])
        header[field] = crypto.encode_bytes(value[:-1] + bytes([value[-1] ^ 1]))
    elif field == "file_id":
        header[field] = "a" * 32
    elif field == "version":
        header[field] = 2
    elif field == "kdf":
        header[field]["iterations"] += 1
    else:
        header[field] = "unsupported"
    changed = codec.FileEnvelope(header, wrapped, payload).serialize()
    with pytest.raises((InvalidStore, AuthenticationFailed)):
        envelope = codec.parse(changed)
        codec.open_payload(envelope, codec.unwrap(envelope, PASSWORD))
    # A cached file key must not bypass header or wrapped-key authentication.
    with pytest.raises((InvalidStore, AuthenticationFailed)):
        envelope = codec.parse(changed)
        codec.open_payload(envelope, bytes.fromhex(manifest["file_key_hex"]))


@pytest.mark.parametrize(
    "field,value",
    [
        ("memory_kib", 10**9),
        ("iterations", 10000),
        ("lanes", 100),
        ("memory_kib", True),
        ("lanes", 1.0),
    ],
)
def test_untrusted_kdf_limits_are_checked_without_derivation(
    fixed_file, monkeypatch, field, value
):
    raw, _ = fixed_file
    envelope = codec.parse(raw)
    envelope.header["kdf"][field] = value
    calls = []
    monkeypatch.setattr(crypto, "Argon2id", lambda **kwargs: calls.append(kwargs))
    with pytest.raises(InvalidStore):
        codec.parse(envelope.serialize())
    assert calls == []


@pytest.mark.parametrize("operation", ["derive", "encrypt", "decrypt"])
def test_missing_backend_has_no_weaker_fallback(fixed_file, monkeypatch, operation):
    raw, _ = fixed_file
    envelope = codec.parse(raw)
    calls = []

    def unavailable(*args, **kwargs):
        calls.append((args, kwargs))
        raise UnsupportedAlgorithm("PUBLIC-TEST-private-backend-details")

    monkeypatch.setattr(
        crypto, "Argon2id" if operation == "derive" else "AESGCM", unavailable
    )
    with pytest.raises(UnsupportedProtection) as raised:
        if operation == "encrypt":
            codec.seal(b"PUBLIC-TEST-data", PASSWORD)
        else:
            codec.unwrap(envelope, PASSWORD)
    assert len(calls) == 1
    assert str(raised.value) == "protection_unavailable"
    assert raised.value.__cause__ is None and raised.value.__context__ is None


def test_repeated_nonce_is_rejected_before_derivation(monkeypatch):
    def forbidden(**kwargs):
        raise AssertionError("Derivation must not run")

    monkeypatch.setattr(codec.secrets, "token_bytes", lambda size: bytes(size))
    monkeypatch.setattr(crypto, "Argon2id", forbidden)
    with pytest.raises(UnsupportedProtection):
        codec.seal(b"PUBLIC-TEST-data", PASSWORD)


@pytest.mark.parametrize("key", [bytes(16), bytes(24), bytes(31), bytes(33)])
def test_only_aes_256_file_keys_are_accepted(fixed_file, key):
    raw, _ = fixed_file
    with pytest.raises(InvalidStore):
        codec.open_payload(codec.parse(raw), key)


def test_size_truncation_and_header_json_bounds(fixed_file, monkeypatch):
    raw, _ = fixed_file
    envelope = codec.parse(raw)
    for data in (
        b"",
        raw[:8],
        raw[:12],
        raw[: -len(envelope.payload)],
        codec.MAGIC + (4097).to_bytes(4, "big"),
    ):
        with pytest.raises(InvalidStore):
            codec.parse(data)
    for header in (
        b'{"version":1,"version":1}',
        b'{"version":NaN}',
        b'"not an object"',
    ):
        with pytest.raises(InvalidStore):
            codec.parse(
                codec.MAGIC + len(header).to_bytes(4, "big") + header + bytes(64)
            )
    monkeypatch.setattr(codec, "MAXIMUM_PLAINTEXT", 1)
    with pytest.raises(InvalidStore):
        codec.seal(b"ab", PASSWORD)
    with pytest.raises(InvalidStore):
        codec.parse(raw)
    monkeypatch.setattr(codec, "MAXIMUM_SIZE", len(raw) - 1)
    with pytest.raises(InvalidStore):
        codec.parse(raw)
    with pytest.raises(InvalidStore):
        envelope.serialize()


def test_vault_and_external_file_contexts_are_distinct(fixed_file):
    raw, _ = fixed_file
    with pytest.raises(InvalidStore):
        vault_format.parse(raw)
    vault = FIXTURES.parent / "vault-v1/sample.vault"
    with pytest.raises(InvalidStore):
        codec.parse(vault.read_bytes())
