"""Protected readers retain references, including captured legacy inputs."""

import asyncio
import base64
import hashlib

import pytest
from cryptography.fernet import Fernet

from w3plex.config.reading import load_reference_config
from w3plex.security import SecretRef
from w3plex.security.errors import PermissionDenied
from w3plex.security.legacy import LegacyContext
from w3plex.utils.loader import FileLoader, SecretFileLoader

PASSWORD = b"PUBLIC-TEST-snapshot-password"


def test_line_reader_preserves_bom_comments_unicode_and_raw_filter(secret_store):
    source = secret_store.capture(
        b"\xef\xbb\xbf # ignored\r\n\r\n one \r\n\tcaf\xc3\xa9\t\n"
    )
    values = asyncio.run(FileLoader.from_secret(source).process())
    assert all(isinstance(value, SecretRef) for value in values)
    assert [value.ref(silent=True) for value in values] == ["one", "café"]
    selected = asyncio.run(SecretFileLoader(source, filter="^\\t").process())
    assert [value.ref(silent=True) for value in selected] == ["café"]
    secret_store._vault.lock()
    secret_store._vault.unlock(PASSWORD)
    assert [value.ref(silent=True) for value in values] == ["one", "café"]


def test_line_transform_receives_reference_and_can_skip_items(secret_store):
    source = secret_store.capture(b"one\ntwo\n")
    received = []

    def transform(value):
        received.append(value)
        return value if len(received) == 1 else None

    assert asyncio.run(SecretFileLoader(source).process(transform)) == received[:1]
    assert all(isinstance(value, SecretRef) for value in received)


def test_enc1_is_captured_once_without_modifying_original(secret_store, tmp_path):
    password = "PUBLIC-TEST-legacy-password"
    key = base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())
    encrypted = b"ENC1" + Fernet(key).encrypt(b"one\ntwo\n")
    filename = tmp_path / "legacy.enc"
    filename.write_bytes(encrypted)
    legacy = LegacyContext(None, input_handler=lambda request: password)
    captured = secret_store.capture_file(filename, legacy=legacy)
    assert filename.read_bytes() == encrypted
    values = asyncio.run(SecretFileLoader(captured).process())
    filename.unlink()
    legacy.lock()
    secret_store._vault.lock()
    secret_store._vault.unlock(PASSWORD)
    assert [value.ref(silent=True) for value in values] == ["one", "two"]


def test_yaml_config_returns_refs_and_captures_expanded_included_values(secret_store):
    source = secret_store.capture(b"debank: !include debank.yaml\ncount: 3\n")
    included = secret_store.capture(b"api_key: ${TOKEN}\nwallet: 0x1234\n")
    config = load_reference_config(
        source,
        filename="w3plex.yaml",
        includes={"debank.yaml": included},
        environment={"TOKEN": "PUBLIC-TEST-config-token"},
    )
    assert isinstance(config.debank.api_key, SecretRef)
    assert config.count == 3
    assert config.debank.wallet.ref(silent=True) == "0x1234"
    secret_store._vault.lock()
    secret_store._vault.unlock(PASSWORD)
    assert config.debank.api_key.ref(silent=True) == "PUBLIC-TEST-config-token"


def test_config_include_cannot_read_unregistered_file(secret_store, tmp_path):
    private = tmp_path / "private.yaml"
    private.write_text("api_key: PUBLIC-TEST-other-value\n")
    source = secret_store.capture(f"debank: !include {private}\n".encode())
    with pytest.raises(PermissionDenied):
        load_reference_config(source, environment={})
