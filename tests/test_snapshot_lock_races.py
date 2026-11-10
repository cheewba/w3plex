"""Configured source capture must not import secrets into a later session."""

import base64
import hashlib

import pytest
from cryptography.fernet import Fernet

from w3plex.security.errors import PermissionDenied
from w3plex.security.legacy import LegacyContext

FILE_PASSWORD = "PUBLIC-TEST-file-password"


def encrypted_source(path):
    key = base64.urlsafe_b64encode(hashlib.sha256(FILE_PASSWORD.encode()).digest())
    path.write_bytes(b"ENC1" + Fernet(key).encrypt(b"PUBLIC-TEST-private-value"))


def test_locked_capture_does_not_read_a_source_or_request_password(
    vault, secret_store, tmp_path, monkeypatch
):
    path = tmp_path / "data.enc"
    encrypted_source(path)
    legacy = LegacyContext(
        None,
        input_handler=lambda request: pytest.fail(
            "Locked capture requested a password"
        ),
    )
    vault.lock()
    monkeypatch.setattr(
        "w3plex.security.refs.snapshot_file",
        lambda path: pytest.fail("Locked capture opened a private source"),
    )
    with pytest.raises(PermissionDenied):
        secret_store.capture_file(path, context=legacy)


@pytest.mark.parametrize("reopen", [False, True])
def test_private_input_lock_invalidates_capture(
    vault, vault_password, secret_store, tmp_path, reopen
):
    path = tmp_path / "data.enc"
    encrypted_source(path)
    original = vault.path.read_bytes()

    def password(request):
        vault.lock()
        if reopen:
            vault.unlock(vault_password)
        return FILE_PASSWORD

    legacy = LegacyContext(None, input_handler=password)
    try:
        with pytest.raises(PermissionDenied):
            secret_store.capture_file(path, context=legacy)
        assert vault.path.read_bytes() == original
    finally:
        legacy.lock()
