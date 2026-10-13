"""Encrypted snapshot persistence and local handle lifetimes; synthetic data only."""

import base64
import pickle

import pytest

from w3plex.security.errors import InvalidStore, PermissionDenied
from w3plex.security.refs import SecretStore
from w3plex.security.storage import CiphertextFile
from w3plex.security.vault import Vault

PASSWORD = b"PUBLIC-TEST-snapshot-password"
VALUE = b"PUBLIC-TEST-snapshot-value-19041"


def test_source_change_and_delete_do_not_change_snapshot(secret_store, tmp_path):
    source = tmp_path / "source.txt"
    source.write_bytes(VALUE)
    ref = secret_store.capture_file(source)
    secret_store._vault.lock()
    source.write_bytes(b"PUBLIC-TEST-replacement")
    source.unlink()
    with pytest.raises(PermissionDenied):
        ref._use(lambda value: value)
    secret_store._vault.unlock(PASSWORD)
    assert ref._use(lambda value: value) == VALUE
    assert ref.identifier == secret_store.reference(ref.identifier).identifier


def test_reopen_does_not_need_source_file(secret_store):
    ref = secret_store.capture(VALUE)
    identifier = ref.identifier
    storage, protection = secret_store._vault._storage, secret_store._vault._protection
    secret_store._vault.close()
    reopened = Vault(CiphertextFile(storage.path), protection=protection)
    try:
        reopened.unlock(PASSWORD)
        restored = SecretStore(reopened).reference(identifier)
        assert restored._use(lambda value: value) == VALUE
    finally:
        reopened.close()


def test_capture_is_encrypted_and_recapture_has_a_new_id(secret_store):
    first, second = secret_store.capture(VALUE), secret_store.capture(VALUE)
    assert first.identifier != second.identifier
    for path in secret_store._vault._storage.path.parent.iterdir():
        raw = path.read_bytes()
        for value in (VALUE, PASSWORD):
            assert value not in raw
            assert value.hex().encode() not in raw
            assert base64.b64encode(value) not in raw
    assert VALUE.decode() not in repr(first)
    with pytest.raises(PermissionDenied):
        pickle.dumps(first)


def test_empty_and_large_data_preserve_existing_record_size_rules(secret_store):
    assert secret_store.capture(b"")._use(lambda value: value) == b""
    value = b"x" * 70000
    assert secret_store.capture(value)._use(len) == len(value)
    with pytest.raises(InvalidStore):
        secret_store.capture(b"x" * (1024 * 1024 + 1))


def test_unknown_id_and_host_check_refuse_use(secret_store):
    with pytest.raises(PermissionDenied):
        secret_store.reference("0" * 32)._use(lambda value: value)
    ref = secret_store.capture(VALUE)
    secret_store._check_host = lambda: (_ for _ in ()).throw(PermissionDenied())
    with pytest.raises(PermissionDenied):
        ref._use(lambda value: value)


def test_failed_capture_keeps_previous_encrypted_snapshot(secret_store, monkeypatch):
    ref = secret_store.capture(VALUE)
    original = secret_store._vault._storage.path.read_bytes()

    def failed(*args, **kwargs):
        raise OSError("PUBLIC-TEST-private-error")

    with monkeypatch.context() as patch:
        patch.setattr(secret_store._vault._storage, "write", failed)
        with pytest.raises(Exception) as caught:
            secret_store.capture(b"PUBLIC-TEST-new-value")
        assert "PUBLIC-TEST-private-error" not in str(caught.value)
    assert secret_store._vault._storage.path.read_bytes() == original
    secret_store._vault.unlock(PASSWORD)
    assert ref._use(lambda value: value) == VALUE
