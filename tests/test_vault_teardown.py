"""Closing an owner releases storage even when lock notification fails."""

import json
import os
from pathlib import Path

import pytest

from w3plex.security import EncryptedIOContext
from w3plex.security.errors import PermissionDenied, SecurityError
from w3plex.security.memory import ProcessProtection
from w3plex.security.storage import CiphertextFile
from w3plex.security.vault import Vault

FIXTURES = Path(__file__).parent / "fixtures/security"
MANIFEST = json.loads((FIXTURES / "vault-v1.json").read_text())


@pytest.fixture(params=["vault", "owning-context"])
def unlocked_owner(tmp_path, request):
    path = tmp_path / "vault"
    path.write_bytes((FIXTURES / "vault-v1.bin").read_bytes())
    protection = ProcessProtection()
    protection.activate()
    if request.param == "vault":
        vault = Vault(CiphertextFile(path), protection=protection)
        vault.unlock(MANIFEST["password"].encode())
        owner = vault
    else:
        owner = EncryptedIOContext(
            protection=protection,
            keystore_path=path,
            input_handler=lambda _: MANIFEST["password"],
        )
        owner.unlock_keystore()
        vault = owner._keystore
    try:
        yield owner, vault
    finally:
        vault.bind_lock(None)
        owner.close()
        vault.close()


def assert_terminal(vault, descriptor):
    assert not vault.is_unlocked and vault._closed
    assert vault._storage._fd is None
    with pytest.raises(OSError):
        os.fstat(descriptor)
    with pytest.raises(PermissionDenied):
        vault.unlock(MANIFEST["password"].encode())


def test_normal_close_is_terminal_and_idempotent(unlocked_owner):
    owner, vault = unlocked_owner
    descriptor = vault._storage._fd
    original = vault.path.read_bytes()
    owner.close()
    assert_terminal(vault, descriptor)
    owner.close()
    assert_terminal(vault, descriptor)
    assert vault.path.read_bytes() == original


@pytest.mark.parametrize("failure", ["security-error", "cancellation"])
def test_notification_failure_cannot_leave_storage_open(unlocked_owner, failure):
    owner, vault = unlocked_owner
    descriptor = vault._storage._fd
    original = vault.path.read_bytes()

    class PrivateFailure(SecurityError):
        code = "PUBLIC-TEST-private-listener-failure"

    class Host:
        def locked(self):
            if failure == "cancellation":
                raise KeyboardInterrupt()
            raise PrivateFailure()

    host = Host()
    vault.bind_lock(host.locked)
    expected = KeyboardInterrupt if failure == "cancellation" else SecurityError
    with pytest.raises(expected) as result:
        owner.close()
    if failure == "security-error":
        assert type(result.value) is SecurityError
        assert str(result.value) == "security_error"
        assert result.value.__context__ is None and result.value.__cause__ is None
    assert_terminal(vault, descriptor)
    assert vault.path.read_bytes() == original


def test_borrowed_context_close_leaves_vault_owned_by_its_host(tmp_path):
    path = tmp_path / "vault"
    path.write_bytes((FIXTURES / "vault-v1.bin").read_bytes())
    protection = ProcessProtection()
    protection.activate()
    vault = Vault(CiphertextFile(path), protection=protection)
    vault.unlock(MANIFEST["password"].encode())
    owner = EncryptedIOContext(protection=protection, keystore=vault)
    descriptor = vault._storage._fd
    try:
        owner.close()
        assert not vault.is_unlocked and not vault._closed
        assert os.fstat(descriptor)
        vault.unlock(MANIFEST["password"].encode())
        assert vault.is_unlocked
    finally:
        owner.close()
        vault.close()
