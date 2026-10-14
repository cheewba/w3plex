"""Encrypted file-key persistence, temporary reuse and lock races."""

import hashlib
import json
import threading
from pathlib import Path

import pytest

from w3plex.security import EncryptedIOContext, file_format
from w3plex.security.errors import (
    AuthenticationFailed,
    InteractionRequired,
    InvalidStore,
    PermissionDenied,
    SecurityError,
    UnsupportedProtection,
)
from w3plex.security.memory import ProcessProtection
from w3plex.security.storage import CiphertextFile
from w3plex.security.vault import Vault

FIXTURES = Path(__file__).parent / "fixtures/file-v1"
MASTER = b"PUBLIC-TEST-modern-master"
PASSWORD = "PUBLIC-TEST-file-v1-password"


@pytest.fixture
def keystore(tmp_path):
    protection = ProcessProtection()
    protection.activate()
    directory = tmp_path / "secret-store"
    directory.mkdir(mode=0o700)
    vault = Vault(CiphertextFile(directory / "keys.vault"), protection=protection)
    vault.create(MASTER)
    vault.unlock(MASTER)
    try:
        yield vault
    finally:
        vault.close()


def read(owner):
    with owner.open(FIXTURES / "sample.enc", "rb") as stream:
        return stream.read()


def test_existing_accessible_keystore_needs_no_permission_repair(tmp_path):
    directory = tmp_path / "existing"
    directory.mkdir(mode=0o755)
    directory.chmod(0o755)
    path = directory / "keys.vault"
    requests = []

    def answer(request):
        requests.append(request.kind)
        return PASSWORD if request.kind == "file" else MASTER.decode()

    owner = EncryptedIOContext(
        keystore_path=path, persist_keys=True, input_handler=answer
    )
    try:
        expected = bytes.fromhex(
            json.loads((FIXTURES / "manifest.json").read_text())["plaintext_hex"]
        )
        owner.enable()
        with open(FIXTURES / "sample.enc", "rb") as stream:
            assert stream.read() == expected
        assert requests == ["master", "master_confirm", "file"]
        assert directory.stat().st_mode & 0o777 == 0o755
        path.chmod(0o644)
        original = path.read_bytes()
        owner.lock()
        requests.clear()
        with open(FIXTURES / "sample.enc", "rb") as stream:
            assert stream.read() == expected
        assert requests == ["master"]
        assert path.read_bytes() == original
        assert path.stat().st_mode & 0o777 == 0o644
        assert directory.stat().st_mode & 0o777 == 0o755
    finally:
        owner.close()


def test_remembered_key_reopens_without_file_password_and_no_plaintext_on_disk(
    keystore,
):
    requests = []
    owner = EncryptedIOContext(
        protection=keystore.protection,
        keystore=keystore,
        persist_keys=True,
        input_handler=lambda request: requests.append(request.kind) or PASSWORD,
    )
    try:
        value = read(owner)
        stored = keystore.path.read_bytes()
        assert read(owner) == value and keystore.path.read_bytes() == stored
        assert requests == ["file"] and owner._keys == {}
        manifest = json.loads((FIXTURES / "manifest.json").read_text())
        for secret in (
            MASTER,
            PASSWORD.encode(),
            bytes.fromhex(manifest["file_key_hex"]),
        ):
            assert secret not in stored
        path, protection = keystore.path, keystore.protection
    finally:
        owner.close()
    reopened = Vault(CiphertextFile(path), protection=protection)
    replies = []
    new_owner = EncryptedIOContext(
        protection=protection,
        keystore=reopened,
        input_handler=lambda request: replies.append(request.kind) or MASTER.decode(),
    )
    try:
        assert read(new_owner) == value
        assert replies == ["master"]
        assert path.read_bytes() == stored
    finally:
        new_owner.close()
        reopened.close()


def test_unsaved_key_reuses_memory_and_underlying_lock_clears_it(keystore):
    before = keystore.path.read_bytes()
    requests = []
    owner = EncryptedIOContext(
        protection=keystore.protection,
        keystore=keystore,
        input_handler=lambda request: requests.append(request.kind) or PASSWORD,
    )
    try:
        assert read(owner) == read(owner)
        assert requests == ["file"] and keystore.path.read_bytes() == before
        buffer = next(iter(owner._keys.values()))
        keystore.lock()
        assert owner._keys == {}
        with pytest.raises(UnsupportedProtection):
            buffer.copy_bytes()
    finally:
        owner.close()


@pytest.mark.parametrize("format_name", ["modern", "legacy"])
@pytest.mark.parametrize("output", ["missing", "existing", "inplace"])
@pytest.mark.parametrize("reunlock", [False, True])
def test_vault_lock_after_decryption_prevents_plaintext_output(
    keystore, tmp_path, monkeypatch, format_name, output, reunlock
):
    directory = (
        FIXTURES if format_name == "modern" else FIXTURES.parent / "legacy-security"
    )
    manifest = json.loads((directory / "manifest.json").read_text())
    source = tmp_path / "source.enc"
    source.write_bytes((directory / "sample.enc").read_bytes())
    destination = source if output == "inplace" else tmp_path / "output"
    if output == "existing":
        destination.write_bytes(b"PUBLIC-TEST-previous-output")
    original = destination.read_bytes() if destination.exists() else None
    owner = EncryptedIOContext(
        protection=keystore.protection,
        keystore=keystore,
        input_handler=lambda _: (
            PASSWORD if format_name == "modern" else manifest["file_password"]
        ),
    )
    decrypt = owner.decrypt_bytes
    failures = []

    def revoke():
        try:
            keystore.lock()
            if reunlock:
                keystore.unlock(MASTER)
        except BaseException as exc:
            failures.append(exc)

    def decrypted(*args, **kwargs):
        result = decrypt(*args, **kwargs)
        worker = threading.Thread(target=revoke, daemon=True)
        worker.start()
        worker.join(timeout=3)
        assert not worker.is_alive(), "Private input/decryption held the vault mutex"
        assert failures == []
        return result

    monkeypatch.setattr(owner, "decrypt_bytes", decrypted)
    try:
        with pytest.raises(PermissionDenied):
            owner.decrypt_file(source, dst=destination, use_keystore=True)
        assert (destination.read_bytes() if destination.exists() else None) == original
        assert not list(tmp_path.glob("*.tmp"))
    finally:
        owner.close()


def test_initially_locked_vault_checkpoint_survives_decryption_boundary(
    keystore, tmp_path, monkeypatch
):
    keystore.lock()
    source = tmp_path / "source.enc"
    source.write_bytes((FIXTURES / "sample.enc").read_bytes())
    requests = []

    def answer(request):
        requests.append(request.kind)
        return MASTER.decode() if request.kind == "master" else PASSWORD

    owner = EncryptedIOContext(
        protection=keystore.protection, keystore=keystore, input_handler=answer
    )
    decrypt = owner.decrypt_bytes

    def decrypted(*args, **kwargs):
        result = decrypt(*args, **kwargs)
        keystore.lock()
        keystore.unlock(MASTER)
        return result

    monkeypatch.setattr(owner, "decrypt_bytes", decrypted)
    try:
        with pytest.raises(PermissionDenied):
            owner.decrypt_file(source, use_keystore=True)
        assert requests == ["master", "file"]
        assert not source.with_suffix(".dec").exists()
    finally:
        owner.close()


def test_plaintext_commit_holds_borrowed_vault_mutex(keystore, tmp_path, monkeypatch):
    source = tmp_path / "source.enc"
    source.write_bytes((FIXTURES / "sample.enc").read_bytes())
    owner = EncryptedIOContext(
        protection=keystore.protection,
        keystore=keystore,
        input_handler=lambda _: PASSWORD,
    )
    write = CiphertextFile.write_plaintext
    entered, locked = threading.Event(), threading.Event()
    worker = None

    def revoke():
        entered.set()
        keystore.lock()
        locked.set()

    def committing(storage, *args, **kwargs):
        nonlocal worker
        worker = threading.Thread(target=revoke, daemon=True)
        worker.start()
        assert entered.wait(timeout=2)
        assert not locked.wait(timeout=0.1), "Vault locked during plaintext commit"
        return write(storage, *args, **kwargs)

    monkeypatch.setattr(CiphertextFile, "write_plaintext", committing)
    try:
        result = owner.decrypt_file(source, use_keystore=True)
        assert result.read_bytes() == bytes.fromhex(
            json.loads((FIXTURES / "manifest.json").read_text())["plaintext_hex"]
        )
        worker.join(timeout=3)
        assert locked.is_set() and not worker.is_alive()
    finally:
        if worker is not None:
            worker.join(timeout=3)
        owner.close()


def test_shared_vault_lock_clears_each_context_without_replacing_primary_owner(
    keystore,
):
    class Host:
        called = 0

        def locked(self):
            self.called += 1

    host = Host()
    keystore.bind_lock(host.locked)
    owners = [
        EncryptedIOContext(
            protection=keystore.protection,
            keystore=keystore,
            input_handler=lambda _: PASSWORD,
        )
        for _ in range(2)
    ]
    try:
        for owner in owners:
            read(owner)
            assert owner._keys
        # Notifications must not acquire a context's operation mutex while
        # holding the vault mutex; that would invert the read lock order.
        with owners[0]._mutex:
            worker = threading.Thread(target=keystore.lock, daemon=True)
            worker.start()
            worker.join(timeout=2)
            assert not worker.is_alive()
        assert host.called == 1 and all(owner._keys == {} for owner in owners)
    finally:
        keystore.bind_lock(None)
        for owner in owners:
            owner.close()


@pytest.mark.parametrize("lock_owner", ["context", "vault"])
def test_lock_during_file_input_cannot_save_key(keystore, lock_owner):
    before = keystore.path.read_bytes()
    owner = None

    def answer(request):
        if lock_owner == "context":
            owner.lock()
        else:
            keystore.lock()
            keystore.unlock(MASTER)
        return PASSWORD

    owner = EncryptedIOContext(
        protection=keystore.protection,
        keystore=keystore,
        persist_keys=True,
        input_handler=answer,
    )
    try:
        with pytest.raises(PermissionDenied):
            read(owner)
        assert keystore.path.read_bytes() == before and owner._keys == {}
    finally:
        owner.close()


@pytest.mark.parametrize("phase", ["input", "seal"])
@pytest.mark.parametrize("output", ["missing", "existing", "inplace"])
def test_vault_reunlock_during_encryption_cannot_save_or_write(
    keystore, tmp_path, monkeypatch, phase, output
):
    before = keystore.path.read_bytes()
    source = tmp_path / "source"
    original = b"PUBLIC-TEST-encryption-source"
    source.write_bytes(original)
    destination = source if output == "inplace" else tmp_path / "destination"
    if output == "existing":
        destination.write_bytes(b"PUBLIC-TEST-existing-output")
    previous = destination.read_bytes() if destination.exists() else None

    def revoke():
        keystore.lock()
        keystore.unlock(MASTER)

    def answer(request):
        if phase == "input":
            revoke()
        return PASSWORD

    seal = file_format.seal

    def interrupted_seal(*args, **kwargs):
        result = seal(*args, **kwargs)
        revoke()
        return result

    if phase == "seal":
        monkeypatch.setattr(file_format, "seal", interrupted_seal)
    owner = EncryptedIOContext(
        protection=keystore.protection, keystore=keystore, input_handler=answer
    )
    try:
        with pytest.raises(PermissionDenied):
            owner.encrypt_file(source, dst=destination, add_to_keystore=True)
        assert source.read_bytes() == original
        assert keystore.path.read_bytes() == before
        assert destination.exists() is (previous is not None)
        if previous is not None:
            assert destination.read_bytes() == previous
    finally:
        owner.close()


def test_vault_reunlock_during_data_encryption_cannot_save(keystore, monkeypatch):
    before = keystore.path.read_bytes()
    seal = file_format.seal

    def interrupted_seal(*args, **kwargs):
        result = seal(*args, **kwargs)
        keystore.lock()
        keystore.unlock(MASTER)
        return result

    monkeypatch.setattr(file_format, "seal", interrupted_seal)
    owner = EncryptedIOContext(protection=keystore.protection, keystore=keystore)
    try:
        with pytest.raises(PermissionDenied):
            owner.encrypt_data("PUBLIC-TEST-data", password=PASSWORD)
        assert keystore.path.read_bytes() == before
    finally:
        owner.close()


def test_wrong_master_and_cancelled_creation_preserve_store(keystore, tmp_path):
    before = keystore.path.read_bytes()
    keystore.lock()
    owner = EncryptedIOContext(
        protection=keystore.protection,
        keystore=keystore,
        input_handler=lambda _: "PUBLIC-TEST-wrong-master",
    )
    try:
        with pytest.raises(AuthenticationFailed):
            read(owner)
        assert keystore.path.read_bytes() == before and owner._keys == {}
    finally:
        owner.close()
    missing = Vault(
        CiphertextFile(tmp_path / "new.vault"), protection=keystore.protection
    )
    values = iter([MASTER.decode(), "PUBLIC-TEST-mismatch"])
    owner = EncryptedIOContext(
        protection=keystore.protection,
        keystore=missing,
        input_handler=lambda _: next(values),
    )
    try:
        with pytest.raises(AuthenticationFailed):
            owner.unlock_keystore()
        assert not missing.path.exists()
    finally:
        owner.close()
        missing.close()


def test_new_keystore_requires_master_confirmation_and_never_changes_legacy(
    keystore, tmp_path
):
    missing = Vault(
        CiphertextFile(tmp_path / "new.vault"), protection=keystore.protection
    )
    legacy = tmp_path / "legacy.bin"
    original = b"PUBLIC-TEST-legacy-source-preserved"
    legacy.write_bytes(original)
    kinds = []

    def answer(request):
        kinds.append(request.kind)
        return PASSWORD if request.kind == "file" else MASTER.decode()

    owner = EncryptedIOContext(
        protection=keystore.protection,
        keystore=missing,
        persist_keys=True,
        legacy_keystore_path=legacy,
        input_handler=answer,
    )
    try:
        assert read(owner)
        assert kinds == ["master", "master_confirm", "file"]
        assert legacy.read_bytes() == original
        assert missing.path.stat().st_mode & 0o777 == 0o600
        assert missing.identifiers()
    finally:
        owner.close()
        missing.close()


@pytest.mark.parametrize("values", [[b"wrong size"], [bytes(32), bytes(32)]])
def test_ambiguous_or_invalid_stored_key_fails_without_file_input(keystore, values):
    raw = (FIXTURES / "sample.enc").read_bytes()
    metadata = {
        "context": "w3plex.file",
        "fingerprint": hashlib.sha256(raw).hexdigest(),
    }
    for value in values:
        keystore.save(value, metadata=metadata)
    owner = EncryptedIOContext(
        protection=keystore.protection,
        keystore=keystore,
        input_handler=lambda _: pytest.fail("No file password fallback"),
    )
    try:
        with pytest.raises(InvalidStore):
            read(owner)
    finally:
        owner.close()


def test_explicit_password_is_checked_even_with_cached_key(keystore):
    owner = EncryptedIOContext(
        protection=keystore.protection, input_handler=lambda _: PASSWORD
    )
    try:
        read(owner)
        with pytest.raises(AuthenticationFailed):
            owner.decrypt_bytes(
                (FIXTURES / "sample.enc").read_bytes(),
                source="cached",
                password="PUBLIC-TEST-wrong-password",
            )
    finally:
        owner.close()


def test_private_input_error_has_no_secret_exception_chain(keystore):
    def broken(request):
        raise ValueError(PASSWORD)

    owner = EncryptedIOContext(protection=keystore.protection, input_handler=broken)
    try:
        with pytest.raises(SecurityError) as raised:
            read(owner)
        assert PASSWORD not in str(raised.value)
        assert raised.value.__context__ is None and raised.value.__cause__ is None
    finally:
        owner.close()


def test_failure_of_one_listener_does_not_skip_other_key_cleanup(keystore):
    class Broken:
        def locked(self):
            raise ValueError(PASSWORD)

    host = Broken()
    owner = EncryptedIOContext(
        protection=keystore.protection,
        keystore=keystore,
        input_handler=lambda _: PASSWORD,
    )
    read(owner)
    keystore.bind_lock(host.locked)
    try:
        with pytest.raises(SecurityError) as raised:
            keystore.lock()
        assert owner._keys == {} and not keystore.is_unlocked
        assert raised.value.__context__ is None and raised.value.__cause__ is None
        assert PASSWORD not in str(raised.value)
    finally:
        keystore.bind_lock(None)
        owner.close()


def test_interrupted_host_listener_still_clears_context_keys(keystore):
    class Interrupted:
        def locked(self):
            raise KeyboardInterrupt

    host = Interrupted()
    owner = EncryptedIOContext(
        protection=keystore.protection,
        keystore=keystore,
        input_handler=lambda _: PASSWORD,
    )
    read(owner)
    keystore.bind_lock(host.locked)
    try:
        with pytest.raises(KeyboardInterrupt):
            keystore.lock()
        assert owner._keys == {} and not keystore.is_unlocked
    finally:
        keystore.bind_lock(None)
        owner.close()


def test_separate_keystores_do_not_reuse_another_owners_key(keystore, tmp_path):
    other = Vault(
        CiphertextFile(tmp_path / "other.vault"), protection=keystore.protection
    )
    other.create(MASTER)
    other.unlock(MASTER)
    first = EncryptedIOContext(
        protection=keystore.protection,
        keystore=keystore,
        persist_keys=True,
        input_handler=lambda _: PASSWORD,
    )
    second = EncryptedIOContext(protection=keystore.protection, keystore=other)
    try:
        read(first)
        with pytest.raises(InteractionRequired):
            read(second)
        assert other.identifiers() == () and second._keys == {}
    finally:
        first.close()
        second.close()
        other.close()


def test_lock_during_master_input_stops_before_confirmation(keystore, tmp_path):
    missing = Vault(
        CiphertextFile(tmp_path / "missing.vault"), protection=keystore.protection
    )
    requests = []
    owner = None

    def answer(request):
        requests.append(request.kind)
        owner.lock()
        return MASTER.decode()

    owner = EncryptedIOContext(
        protection=keystore.protection, keystore=missing, input_handler=answer
    )
    try:
        with pytest.raises(PermissionDenied):
            owner.unlock_keystore()
        assert requests == ["master"] and not missing.path.exists()
    finally:
        owner.close()
        missing.close()
