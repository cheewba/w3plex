"""Encrypted recovery and password replacement across atomic-write failures."""

import base64
import os
import subprocess
import sys

import pytest
from test_security_vault import (
    PASSWORD,
    VALUE,
    protection as protection,  # noqa: PLC0414 -- pytest fixture re-export
    vault as vault,  # noqa: PLC0414 -- pytest fixture re-export
)

from w3plex.security import vault as module
from w3plex.security.contracts import SecretKind, SecretUse
from w3plex.security.errors import (
    AuthenticationFailed,
    PermissionDenied,
    SecurityError,
    UnsupportedProtection,
)
from w3plex.security.storage import CiphertextFile, StoreChanged
from w3plex.security.vault import Vault
from w3plex.security.vault_format import parse


@pytest.mark.parametrize("point", ["file-sync", "replace", "directory-sync"])
def test_failed_password_change_preserves_complete_recoverable_store(
    vault, monkeypatch, point
):
    reference = vault.add(SecretKind.API, VALUE, uses=[SecretUse.HTTP])
    original = vault._storage.read()[0]
    fsync = os.fsync
    calls = 0

    def sync(fd):
        nonlocal calls
        calls += 1
        if (point == "file-sync" and calls == 1) or (
            point == "directory-sync" and calls == 2
        ):
            raise OSError("PUBLIC-TEST-private-sync-details")
        return fsync(fd)

    def replace(*args, **kwargs):
        raise OSError("PUBLIC-TEST-private-replace-details")

    monkeypatch.setattr(os, "fsync", sync)
    if point == "replace":
        monkeypatch.setattr(os, "replace", replace)
    with pytest.raises(SecurityError) as raised:
        vault.change_password(PASSWORD, b"PUBLIC-TEST-replacement")
    assert raised.value.__context__ is None and raised.value.__cause__ is None
    assert vault._key is None
    if point == "directory-sync":
        vault.unlock(b"PUBLIC-TEST-replacement")
    else:
        assert vault._storage.read()[0] == original
        vault.unlock(PASSWORD)
    assert vault.references() == (reference,)
    assert not list(vault._storage.path.parent.glob("*.tmp"))


def test_password_change_rotates_salt_nonces_and_data_key(vault):
    reference = vault.add(SecretKind.API, VALUE, uses=[SecretUse.HTTP])
    before = parse(vault._storage.read()[0])
    old_key = vault._key.copy_bytes()
    vault.change_password(PASSWORD, b"PUBLIC-TEST-replacement")
    after = parse(vault._storage.read()[0])
    assert before.header["store_id"] == after.header["store_id"]
    for field in ("salt", "wrap_nonce", "data_nonce"):
        assert before.header[field] != after.header[field]
    with pytest.raises(AuthenticationFailed):
        vault.unlock(PASSWORD)
    vault.unlock(b"PUBLIC-TEST-replacement")
    assert vault._key.copy_bytes() != old_key
    assert vault.references() == (reference,)
    for path in vault._storage.path.parent.iterdir():
        raw = path.read_bytes()
        for secret in (PASSWORD, VALUE, old_key, b"PUBLIC-TEST-replacement"):
            assert secret not in raw and secret.hex().encode() not in raw
            assert base64.b64encode(secret) not in raw


def test_password_change_requires_both_allocations_before_kdf(vault, monkeypatch):
    original = vault._storage.read()[0]
    allocate = module.LockedBuffer
    allocated = []
    calls = []

    def allocation(value, **kwargs):
        if allocated:
            raise UnsupportedProtection()
        buffer = allocate(value, **kwargs)
        allocated.append(buffer)
        return buffer

    def forbidden(*args, **kwargs):
        calls.append("derive")
        raise AssertionError("No password derivation without replacement memory")

    monkeypatch.setattr(module, "LockedBuffer", allocation)
    monkeypatch.setattr(module, "unwrap", forbidden)
    with pytest.raises(UnsupportedProtection):
        vault.change_password(PASSWORD, b"PUBLIC-TEST-replacement")
    assert calls == [] and allocated[0]._memory is None
    assert vault._key is None
    assert vault._storage.read()[0] == original


def test_backup_does_not_decrypt_records_and_preserves_existing_backup(
    vault, tmp_path, protection, monkeypatch
):
    reference = vault.add(SecretKind.API, VALUE, uses=[SecretUse.HTTP])
    original = vault._storage.read()[0]
    directory = tmp_path / "backup"
    directory.mkdir(mode=0o700)
    with CiphertextFile(directory / "vault") as destination:
        with monkeypatch.context() as patch:

            def forbidden(*args, **kwargs):
                raise AssertionError("Ciphertext backup must not decrypt records")

            patch.setattr(module, "open_payload", forbidden)
            vault.backup(destination)
            assert destination.read()[0] == original
            with pytest.raises(StoreChanged):
                vault.backup(destination)
        restored = Vault(destination, protection=protection)
        restored.unlock(PASSWORD)
        assert restored.references() == (reference,)
        restored.close()


def test_backup_refuses_locked_or_changed_source(vault, tmp_path):
    directory = tmp_path / "backup"
    directory.mkdir(mode=0o700)
    with CiphertextFile(directory / "vault") as destination:
        vault.lock()
        with pytest.raises(PermissionDenied):
            vault.backup(destination)
        assert not destination.path.exists()
        vault.unlock(PASSWORD)
        original = vault._storage.read()[0]
        vault._storage.path.write_bytes(original)
        with pytest.raises(AuthenticationFailed):
            vault.backup(destination)
        assert not destination.path.exists()


@pytest.mark.parametrize("point", ["before-replace", "after-replace"])
def test_process_interruption_during_password_change_is_recoverable(vault, point):
    reference = vault.add(SecretKind.API, VALUE, uses=[SecretUse.HTTP])
    original = vault._storage.read()[0]
    vault.lock()
    script = """import os,sys
from w3plex.security.memory import ProcessProtection
from w3plex.security.storage import CiphertextFile
from w3plex.security.vault import Vault
protection = ProcessProtection()
protection.activate()
replace = os.replace
def interrupted(*args, **kwargs):
    if sys.argv[2] == "before-replace":
        os._exit(42)
    replace(*args, **kwargs)
    os._exit(42)
os.replace = interrupted
vault = Vault(CiphertextFile(sys.argv[1]), protection=protection)
vault.change_password(b"PUBLIC-TEST-master", b"PUBLIC-TEST-replacement")
raise AssertionError("Crash point was not reached")
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", script, str(vault._storage.path), point],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 42, result.stderr
    if point == "before-replace":
        assert vault._storage.read()[0] == original
        vault.unlock(PASSWORD)
    else:
        vault.unlock(b"PUBLIC-TEST-replacement")
    assert vault.references() == (reference,)
    for path in vault._storage.path.parent.iterdir():
        raw = path.read_bytes()
        for secret in (PASSWORD, VALUE, b"PUBLIC-TEST-replacement"):
            assert secret not in raw and secret.hex().encode() not in raw
            assert base64.b64encode(secret) not in raw
