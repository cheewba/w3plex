"""Configured source capture must not import secrets into a later session."""

import base64
import hashlib

import pytest
from cryptography.fernet import Fernet

from w3plex.security.errors import PermissionDenied
from w3plex.security.legacy import LegacyContext

PASSWORD = b"PUBLIC-TEST-snapshot-password"
FILE_PASSWORD = "PUBLIC-TEST-file-password"


def encrypted_source(path):
    key = base64.urlsafe_b64encode(hashlib.sha256(FILE_PASSWORD.encode()).digest())
    path.write_bytes(b"ENC1" + Fernet(key).encrypt(b"PUBLIC-TEST-private-value"))


def test_locked_capture_does_not_read_a_source_or_request_password(
    secret_store, tmp_path, monkeypatch
):
    path = tmp_path / "data.enc"
    encrypted_source(path)
    legacy = LegacyContext(
        None,
        input_handler=lambda request: pytest.fail(
            "Locked capture requested a password"
        ),
    )
    secret_store._vault.lock()
    monkeypatch.setattr(
        "w3plex.security.refs._snapshot_file",
        lambda path: pytest.fail("Locked capture opened a private source"),
    )
    with pytest.raises(PermissionDenied):
        secret_store.capture_file(path, legacy=legacy)


@pytest.mark.parametrize("reopen", [False, True])
def test_private_input_lock_invalidates_capture(secret_store, tmp_path, reopen):
    path = tmp_path / "data.enc"
    encrypted_source(path)
    original = secret_store._vault._storage.read()

    def password(request):
        secret_store._vault.lock()
        if reopen:
            secret_store._vault.unlock(PASSWORD)
        return FILE_PASSWORD

    legacy = LegacyContext(None, input_handler=password)
    try:
        with pytest.raises(PermissionDenied):
            secret_store.capture_file(path, legacy=legacy)
        assert secret_store._vault._storage.read() == original
    finally:
        legacy.lock()
