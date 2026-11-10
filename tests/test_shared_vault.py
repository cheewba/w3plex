"""Explicit shared-store refresh and selected cleanup; synthetic values only."""

import os

import pytest

from w3plex.security import (
    EncryptedIOContext,
    SecretJson,
    SecretStore,
    SecretString,
    file_format,
    vault_format,
)
from w3plex.security.errors import (
    AuthenticationFailed,
    InvalidStore,
    PermissionDenied,
    SecurityError,
    UnsupportedProtection,
)
from w3plex.security.storage import CiphertextFile, StoreChanged, WriterBusy
from w3plex.security.vault import Vault


@pytest.fixture
def owners(vault, vault_password):
    first = vault
    other = Vault(CiphertextFile(first.path), protection=first.protection)
    other.unlock(vault_password)
    try:
        yield first, other
    finally:
        other.close()


def test_reload_uses_retained_key_and_preserves_surviving_extraction(
    vault_password, owners, tmp_path, monkeypatch
):
    first, other = owners
    source = tmp_path / "captured.json"
    source.write_bytes(b'{"nested":["PUBLIC-TEST-survivor"]}')
    parent = SecretStore(first).capture_file(source)
    other.reload()
    restored = SecretStore(other).reference(parent.identifier)
    child = SecretJson(SecretString(restored), ("nested", 0))
    metadata = other.metadata(parent.identifier)
    checkpoint = other.checkpoint()
    source.unlink()
    added = first.save(b"PUBLIC-TEST-added", metadata={"origin": ["synthetic", 1]})
    with pytest.raises(PermissionDenied):
        other.read(added)

    def no_password(*args, **kwargs):
        pytest.fail("Reload tried password unwrapping")

    with monkeypatch.context() as patch:
        patch.setattr("w3plex.security.vault.unwrap", no_password)
        other.reload()
        assert other.read(added) == b"PUBLIC-TEST-added"
        assert other.checkpoint() == checkpoint
        assert child.ref(silent=True) == "PUBLIC-TEST-survivor"
        assert other.metadata(restored.identifier) == metadata
        assert first.delete_entries([added]) == (added,)
        # Cached reads remain deliberate until an explicit refresh.
        assert other.read(added) == b"PUBLIC-TEST-added"
        other.reload()
        with pytest.raises(PermissionDenied):
            other.read(added)
        with pytest.raises(PermissionDenied):
            SecretStore(other).reference(added).ref(silent=True)
        assert child.ref(silent=True) == "PUBLIC-TEST-survivor"
        assert other.checkpoint() == checkpoint
    other.lock()
    assert first.is_unlocked
    with pytest.raises(PermissionDenied):
        other.reload()
    assert not other.is_unlocked
    other.unlock(vault_password)
    assert child.ref(silent=True) == "PUBLIC-TEST-survivor"


def test_delete_batch_is_atomic_idempotent_and_keeps_survivors(
    vault, vault_password, secret_store
):
    keep = vault.save(b"\x00PUBLIC-TEST-survivor\xff", metadata={"opaque": [1, None]})
    remove = vault.save(b"PUBLIC-TEST-removed")
    last = vault.save(b"PUBLIC-TEST-last")
    before = vault.path.read_bytes()

    def invalid_selection():
        yield remove
        yield "not-an-id"

    for invalid in (invalid_selection(), remove, [remove, None], [remove] * 4097):
        with pytest.raises(InvalidStore):
            vault.delete_entries(invalid)
        assert vault.path.read_bytes() == before and vault.is_unlocked
    old = vault_format.parse(before)
    checkpoint = vault.checkpoint()
    assert vault.delete_entries([last, remove, last, "0" * 32]) == (remove, last)
    updated = vault_format.parse(vault.path.read_bytes())
    assert updated.wrapped_key == old.wrapped_key
    assert {k: v for k, v in updated.header.items() if k != "data_nonce"} == {
        k: v for k, v in old.header.items() if k != "data_nonce"
    }
    assert vault.identifiers() == (keep,)
    assert vault.metadata(keep) == {"opaque": [1, None]}
    assert (
        secret_store.reference(keep).ref(silent=True) == b"\x00PUBLIC-TEST-survivor\xff"
    )
    assert vault.checkpoint() == checkpoint
    with pytest.raises(PermissionDenied):
        secret_store.reference(remove).ref(silent=True)
    committed = vault.path.read_bytes()
    assert vault.delete_entries([remove, "0" * 32]) == ()
    assert vault.delete_entries([]) == ()
    assert vault.path.read_bytes() == committed
    vault.lock()
    vault.unlock(vault_password)
    assert vault.identifiers() == (keep,)
    assert vault.read(keep) == b"\x00PUBLIC-TEST-survivor\xff"


@pytest.mark.parametrize("selection", ["present", "absent", "empty"])
def test_stale_delete_locks_without_losing_concurrent_append(
    vault_password, owners, selection
):
    first, other = owners
    remove = first.save(b"PUBLIC-TEST-remove")
    other.reload()
    added = first.save(b"PUBLIC-TEST-concurrent")
    committed = first.path.read_bytes()
    selected = {"present": [remove], "absent": ["0" * 32], "empty": []}[selection]
    with pytest.raises(StoreChanged):
        other.delete_entries(selected)
    assert not other.is_unlocked and first.is_unlocked
    assert first.path.read_bytes() == committed
    other.unlock(vault_password)
    assert other.delete_entries([remove]) == (remove,)
    first.reload()
    assert first.identifiers() == (added,)


def test_delete_contention_refuses_then_requires_authenticated_recovery(
    vault_password, owners
):
    first, other = owners
    remove = first.save(b"PUBLIC-TEST-remove")
    other.reload()
    with first._storage.writer_guard(), pytest.raises(WriterBusy):
        other.delete_entries([remove])
    assert not other.is_unlocked
    other.unlock(vault_password)
    assert other.delete_entries([remove]) == (remove,)
    first.reload()
    assert first.identifiers() == ()


def test_delete_directory_sync_uncertainty_locks_then_rereads(
    vault, vault_password, monkeypatch
):
    keep = vault.save(b"PUBLIC-TEST-survivor")
    remove = vault.save(b"PUBLIC-TEST-remove")
    sync = os.fsync

    def fail_directory(fd):
        if fd == vault._storage._fd:
            raise OSError("PUBLIC-TEST-private-sync-failure")
        sync(fd)

    with monkeypatch.context() as patch:
        patch.setattr(os, "fsync", fail_directory)
        with pytest.raises(SecurityError) as error:
            vault.delete_entries([remove])
        assert str(error.value) == SecurityError.code
        assert error.value.__context__ is None and error.value.__cause__ is None
    assert not vault.is_unlocked
    with pytest.raises(PermissionDenied):
        vault.delete_entries([remove])
    # Publication happened, even though durability acknowledgement failed.
    published = vault.path.read_bytes()
    vault.unlock(vault_password)
    assert vault.identifiers() == (keep,)
    assert vault.delete_entries([remove]) == ()
    assert vault.path.read_bytes() == published
    assert vault.read(keep) == b"PUBLIC-TEST-survivor"


@pytest.mark.parametrize(
    "change",
    [
        "corruption",
        "replacement",
        "rotation",
        "wrapper",
        "records",
        "survivor",
        "missing",
    ],
)
def test_reload_failure_revokes_borrowed_keys_and_notifies_all_owners(
    vault_password, owners, change
):
    first, other = owners
    identifier = first.save(b"PUBLIC-TEST-original", metadata={"type": "synthetic"})
    other.reload()
    context = EncryptedIOContext(protection=other.protection, keystore=other)
    encrypted, _ = file_format.seal(b"PUBLIC-TEST-input", b"PUBLIC-TEST-file-password")
    context._input = lambda _: "PUBLIC-TEST-file-password"
    assert (
        context.decrypt_bytes(
            encrypted.serialize(), source=other.path.parent / "input.enc"
        )
        == b"PUBLIC-TEST-input"
    )
    buffers = list(context._keys.values())
    assert buffers

    class Listener:
        calls = 0

        def locked(self):
            self.calls += 1

    host, observer = Listener(), Listener()
    other.bind_lock(host.locked)
    other.add_lock_listener(observer.locked)
    before = first.path.read_bytes()
    envelope = vault_format.parse(before)
    key = vault_format.unwrap(envelope, vault_password)
    if change == "corruption":
        replacement = vault_format.Envelope(
            envelope.header,
            envelope.wrapped_key,
            envelope.payload[:-1] + bytes([envelope.payload[-1] ^ 1]),
        )
    elif change == "replacement":
        replacement, _ = vault_format.seal(b'{"records":[]}', vault_password)
    elif change == "wrapper":
        # Even a valid same-data-key rewrap is a different unlock identity.
        replacement, _ = vault_format.seal(
            vault_format.open_payload(envelope, key),
            vault_password,
            data_key=key,
            store_id=envelope.header["store_id"],
        )
    elif change == "records":
        replacement = vault_format.update_payload(envelope, key, b'{"records":[{}]}')
    elif change == "survivor":
        replacement = vault_format.update_payload(
            envelope,
            key,
            vault_format.canonical(
                {"records": [{"id": identifier, "value": "", "type": "changed"}]}
            ),
        )
    if change == "rotation":
        first.change_password(vault_password, b"PUBLIC-TEST-rotated")
    elif change == "missing":
        first.path.unlink()
    else:
        first._storage.write(replacement.serialize(), expected=first._storage.read()[1])
    try:
        with pytest.raises(SecurityError) as error:
            other.reload()
        assert type(error.value) in {SecurityError, AuthenticationFailed, InvalidStore}
        assert error.value.__context__ is None and error.value.__cause__ is None
        assert not other.is_unlocked and context._keys == {}
        assert host.calls == observer.calls == 1
        for buffer in buffers:
            with pytest.raises(UnsupportedProtection):
                buffer.copy_bytes()
        with pytest.raises(PermissionDenied):
            other.read(identifier)
        # A failed reload has no persistent mutation. Restore and unlock explicitly.
        if first.path.exists():
            expected = first._storage.read()[1]
        else:
            expected = None
        first._storage.write(before, expected=expected)
        other.unlock(vault_password)
        assert other.read(identifier) == b"PUBLIC-TEST-original"
    finally:
        other.bind_lock(None)
        context.close()


@pytest.mark.parametrize("interrupt", [False, True])
def test_reload_interruption_locks_and_cannot_restore_after_lock(
    vault_password, owners, monkeypatch, interrupt
):
    first, other = owners
    first.save(b"PUBLIC-TEST-latest")

    read = other._storage.read

    def revoked_read():
        result = read()
        other.lock()
        if interrupt:
            raise KeyboardInterrupt
        return result

    with monkeypatch.context() as patch:
        patch.setattr(other._storage, "read", revoked_read)
        with pytest.raises(KeyboardInterrupt if interrupt else PermissionDenied):
            other.reload()
    assert not other.is_unlocked and first.is_unlocked
    other.unlock(vault_password)
    other.reload()
    assert other.identifiers() == first.identifiers()
