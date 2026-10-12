"""Real Argon2id/AEAD and native-memory tests using only public test secrets."""

import base64
import os
import stat
from dataclasses import asdict

import pytest

from w3plex.security.contracts import SecretKind, SecretUse
from w3plex.security.errors import (
    AuthenticationFailed,
    InvalidStore,
    PermissionDenied,
    SecurityError,
    UnsupportedProtection,
)
from w3plex.security.memory import ProcessProtection
from w3plex.security.storage import (
    CiphertextFile,
    StoreChanged,
    UnsafeStorage,
    WriterBusy,
)
from w3plex.security.vault import Vault

PASSWORD = b"PUBLIC-TEST-master"
VALUE = b"PUBLIC-TEST-api-secret-751045"


@pytest.fixture
def protection():
    controls = ProcessProtection()
    controls.activate()
    return controls


@pytest.fixture
def vault(tmp_path, protection):
    directory = tmp_path / "secrets"
    directory.mkdir(mode=0o700)
    store = Vault(CiphertextFile(directory / "vault"), protection=protection)
    store.create(PASSWORD)
    store.unlock(PASSWORD)
    yield store
    store.close()


def test_failed_allocation_prevents_password_derivation(vault, monkeypatch):
    calls = []

    def unavailable(*args, **kwargs):
        raise UnsupportedProtection()

    def derive(*args, **kwargs):
        calls.append("derive")
        raise AssertionError("KDF must not run without locked memory")

    vault.lock()
    monkeypatch.setattr("w3plex.security.vault.LockedBuffer", unavailable)
    monkeypatch.setattr("w3plex.security.vault.unwrap", derive)
    with pytest.raises(UnsupportedProtection):
        vault.unlock(PASSWORD)
    assert calls == []
    assert vault._key is None


def test_record_ids_wallet_validation_and_no_plaintext_persistence(vault):
    references = []
    for kind in (SecretKind.API, SecretKind.RPC, SecretKind.MODEL):
        ref = vault.add(kind, VALUE, uses=[SecretUse.HTTP])
        references.append(ref)
        assert VALUE.decode() not in repr(ref)
        assert ref.address is None
    wallet = vault.add(
        SecretKind.WALLET,
        bytes.fromhex("01" * 32),
        uses=[SecretUse.MESSAGE, SecretUse.TRANSACTION],
    )
    assert wallet.address == "0x1a642f0E3c3aF545E7AcBD38b07251B3990914F1"
    assert len({ref.identifier for ref in references}) == 3
    assert vault.references() == (*references, wallet)
    with pytest.raises(InvalidStore):
        vault.add(SecretKind.WALLET, b"short", uses=[SecretUse.TRANSACTION])
    with pytest.raises(PermissionDenied):
        vault._use_secret(references[0], SecretUse.MESSAGE, lambda value: value)
    assert vault._use_secret(
        references[0], SecretUse.HTTP, lambda value: value == VALUE
    )
    for filename in vault._storage.path.parent.iterdir():
        data = filename.read_bytes()
        for secret in (PASSWORD, VALUE, bytes.fromhex("01" * 32)):
            assert secret not in data
            assert secret.hex().encode() not in data
            assert base64.b64encode(secret) not in data
        assert stat.S_IMODE(filename.stat().st_mode) == 0o600


@pytest.mark.parametrize("kind", [SecretKind.SEED, SecretKind.PASSWORD])
def test_recovery_records_expose_only_public_reference_metadata(vault, kind):
    reference = vault.add(kind, VALUE, uses=[SecretUse.RECOVERY])
    assert asdict(reference) == {
        "identifier": reference.identifier,
        "kind": kind,
        "address": None,
    }
    assert len(reference.identifier) == 32
    assert not hasattr(reference, "key") and not hasattr(reference, "value")
    with pytest.raises(PermissionDenied):
        vault._use_secret(reference, SecretUse.HTTP, lambda value: value)
    assert vault._use_secret(
        reference, SecretUse.RECOVERY, lambda value: value == VALUE
    )
    vault.lock()
    vault.unlock(PASSWORD)
    assert vault.references() == (reference,)


def test_credential_use_does_not_materialize_unrelated_wallet_keys(vault, monkeypatch):
    from w3plex.security import vault as module

    vault.add(SecretKind.WALLET, bytes.fromhex("01" * 32), uses=[SecretUse.MESSAGE])
    reference = vault.add(SecretKind.API, VALUE, uses=[SecretUse.HTTP])
    calls = []

    def forbidden(*args, **kwargs):
        calls.append("wallet")
        raise AssertionError("Reading an API key must not derive wallet keys")

    monkeypatch.setattr(module.EthAccount, "from_key", forbidden)
    assert vault._use_secret(reference, SecretUse.HTTP, lambda value: value == VALUE)
    assert len(vault.references()) == 2
    assert calls == []


def test_invalid_record_types_and_duplicate_ids_do_not_commit(vault, monkeypatch):
    original = vault._storage.read()[0]
    with pytest.raises(InvalidStore):
        vault.add(SecretKind.API, VALUE, uses=["http"])
    with pytest.raises(InvalidStore):
        vault.add(SecretKind.WALLET, bytes.fromhex("01" * 32), uses=[SecretUse.HTTP])
    assert vault._storage.read()[0] == original
    monkeypatch.setattr(
        "w3plex.security.vault.secrets.token_hex", lambda size: "ab" * 16
    )
    with pytest.raises(InvalidStore):
        vault.import_records(
            [
                (SecretKind.API, VALUE, (SecretUse.HTTP,)),
                (SecretKind.API, VALUE, (SecretUse.HTTP,)),
            ]
        )
    assert vault.references() == ()
    assert vault._storage.read()[0] == original


def test_lock_wrong_password_and_corruption_never_replace(vault):
    ref = vault.add(SecretKind.API, VALUE, uses=[SecretUse.HTTP])
    original = vault._storage.path.read_bytes()
    vault.lock()
    with pytest.raises(PermissionDenied):
        vault.references()
    with pytest.raises(AuthenticationFailed) as caught:
        vault.unlock(b"wrong")
    assert caught.value.__context__ is None
    assert vault._key is None
    assert vault._storage.path.read_bytes() == original
    vault.unlock(PASSWORD)
    assert vault.references() == (ref,)
    vault.lock()
    vault._storage.path.write_bytes(original[:-10] + b"corrupt")
    damaged = vault._storage.path.read_bytes()
    with pytest.raises(SecurityError):
        vault.unlock(PASSWORD)
    assert vault._key is None
    assert vault._storage.path.read_bytes() == damaged


def test_password_change_and_encrypted_backup(vault, tmp_path, protection):
    ref = vault.add(SecretKind.API, VALUE, uses=[SecretUse.HTTP])
    original = vault._storage.path.read_bytes()
    with pytest.raises(AuthenticationFailed):
        vault.change_password(b"wrong", b"replacement")
    assert vault._storage.path.read_bytes() == original
    vault.unlock(PASSWORD)
    backup_dir = tmp_path / "backup"
    backup_dir.mkdir(mode=0o700)
    backup = CiphertextFile(backup_dir / "encrypted")
    vault.backup(backup)
    vault.change_password(PASSWORD, b"replacement")
    assert vault._key is None
    with pytest.raises(AuthenticationFailed):
        vault.unlock(PASSWORD)
    vault.unlock(b"replacement")
    assert vault.references() == (ref,)
    recovered = Vault(backup, protection=protection)
    recovered.unlock(PASSWORD)
    assert recovered.references() == (ref,)
    recovered.close()


def test_two_writers_do_not_overwrite_stale_state(vault, protection):
    other = Vault(CiphertextFile(vault._storage.path), protection=protection)
    other.unlock(PASSWORD)
    first = vault.add(SecretKind.API, VALUE, uses=[SecretUse.HTTP])
    with pytest.raises(StoreChanged):
        other.add(SecretKind.API, b"other", uses=[SecretUse.HTTP])
    assert other._key is None
    other.unlock(PASSWORD)
    assert other.references() == (first,)
    other.close()


def test_failed_import_is_not_partially_committed(vault):
    original = vault._storage.path.read_bytes()
    with pytest.raises(InvalidStore):
        vault.import_records(
            [
                (SecretKind.API, VALUE, (SecretUse.HTTP,)),
                (SecretKind.WALLET, b"short", (SecretUse.TRANSACTION,)),
            ]
        )
    assert vault._storage.path.read_bytes() == original
    assert vault.references() == ()


def test_failed_file_commit_preserves_ciphertext(vault, monkeypatch):
    original = vault._storage.path.read_bytes()

    def fail(*args, **kwargs):
        raise OSError("PRIVATE failed path")

    monkeypatch.setattr(os, "replace", fail)
    with pytest.raises(SecurityError) as caught:
        vault.add(SecretKind.API, VALUE, uses=[SecretUse.HTTP])
    assert caught.value.__context__ is None
    assert vault._key is None
    assert vault._storage.path.read_bytes() == original
    assert not list(vault._storage.path.parent.glob("*.tmp"))


def test_posix_storage_aliases_permissions_parent_substitution_and_writer_lock(
    tmp_path,
):
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    path = directory / "vault"
    with CiphertextFile(path) as storage:
        identity = storage.write(b"ciphertext", expected=None)
        assert storage.read() == (b"ciphertext", identity)
        with storage._writer(), pytest.raises(WriterBusy):
            storage.write(b"replacement", expected=identity)
        os.link(path, directory / "alias")
        with pytest.raises(UnsafeStorage):
            storage.read()
        (directory / "alias").unlink()
        path.chmod(0o644)
        with pytest.raises(UnsafeStorage):
            storage.read()
        path.chmod(0o600)
        path.unlink()
        path.symlink_to(directory / "elsewhere")
        with pytest.raises(UnsafeStorage):
            storage.write(b"replacement", expected=identity)
        path.unlink()
        directory.rename(tmp_path / "moved")
        directory.mkdir(mode=0o700)
        with pytest.raises(UnsafeStorage):
            storage.write(b"replacement", expected=None)
    link = tmp_path / "link"
    link.symlink_to(directory, target_is_directory=True)
    with pytest.raises(OSError):
        CiphertextFile(link / "vault")
