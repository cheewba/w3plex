"""Encrypted snapshot persistence and local handle lifetimes; synthetic data only."""

import base64
import os
import pickle

import pytest

from w3plex.security.adapters import SecretJson, SecretString
from w3plex.security.errors import InvalidStore, PermissionDenied, SecurityError
from w3plex.security.refs import SecretStore
from w3plex.security.storage import CiphertextFile
from w3plex.security.vault import Vault

VALUE = b"PUBLIC-TEST-snapshot-value-19041"


def test_child_extraction_and_metadata_restore_without_source_reread(
    vault, vault_password, secret_store, tmp_path
):
    source = tmp_path / "source.json"
    source.write_bytes(b'{"nested":["PUBLIC-TEST-child"]}')
    parent = secret_store.capture_file(source)
    child = SecretJson(SecretString(parent), ("nested", 0))
    metadata = vault.metadata(parent.identifier)
    checkpoint = vault.checkpoint()
    assert child.ref(silent=True) == "PUBLIC-TEST-child"
    vault.lock()
    source.unlink()
    vault.unlock(vault_password)
    assert vault.checkpoint() != checkpoint
    assert child.parent.parent.identifier == parent.identifier
    assert child.path == ("nested", 0)
    assert vault.metadata(parent.identifier) == metadata
    assert child.ref(silent=True) == "PUBLIC-TEST-child"


def test_source_change_and_delete_do_not_change_snapshot(
    vault, vault_password, secret_store, tmp_path
):
    source = tmp_path / "source.txt"
    source.write_bytes(VALUE)
    ref = secret_store.capture_file(source)
    vault.lock()
    source.write_bytes(b"PUBLIC-TEST-replacement")
    source.unlink()
    with pytest.raises(PermissionDenied):
        ref.ref(silent=True)
    vault.unlock(vault_password)
    assert ref.ref(silent=True) == VALUE
    assert ref.identifier == secret_store.reference(ref.identifier).identifier


def test_reopen_does_not_need_source_file(vault, vault_password, secret_store):
    ref = secret_store.capture(VALUE)
    identifier = ref.identifier
    path, protection = vault.path, vault.protection
    vault.close()
    reopened = Vault(CiphertextFile(path), protection=protection)
    try:
        reopened.unlock(vault_password)
        restored = SecretStore(reopened).reference(identifier)
        assert restored.ref(silent=True) == VALUE
    finally:
        reopened.close()


def test_capture_is_encrypted_and_recapture_has_a_new_id(
    vault, vault_password, secret_store
):
    first, second = secret_store.capture(VALUE), secret_store.capture(VALUE)
    assert first.identifier != second.identifier
    for path in vault.path.parent.iterdir():
        raw = path.read_bytes()
        for value in (VALUE, vault_password):
            assert value not in raw
            assert value.hex().encode() not in raw
            assert base64.b64encode(value) not in raw
    assert VALUE.decode() not in repr(first)
    with pytest.raises(PermissionDenied):
        pickle.dumps(first)


def test_empty_and_large_data_preserve_existing_record_size_rules(secret_store):
    assert secret_store.capture(b"").ref(silent=True) == b""
    value = b"x" * 70000
    assert len(secret_store.capture(value).ref(silent=True)) == len(value)
    with pytest.raises(InvalidStore):
        secret_store.capture(b"x" * (1024 * 1024 + 1))


def test_unknown_id_refuses_read(secret_store):
    with pytest.raises(PermissionDenied):
        secret_store.reference("0" * 32).ref(silent=True)


def test_failed_capture_keeps_previous_encrypted_snapshot(
    vault, vault_password, secret_store, monkeypatch
):
    ref = secret_store.capture(VALUE)
    original = vault.path.read_bytes()

    def failed(*args, **kwargs):
        raise OSError("PUBLIC-TEST-private-error")

    with monkeypatch.context() as patch:
        patch.setattr(os, "replace", failed)
        with pytest.raises(SecurityError) as caught:
            secret_store.capture(b"PUBLIC-TEST-new-value")
        assert "PUBLIC-TEST-private-error" not in str(caught.value)
    assert vault.path.read_bytes() == original
    vault.unlock(vault_password)
    assert ref.ref(silent=True) == VALUE
