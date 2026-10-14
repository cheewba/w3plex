"""Exclusive ciphertext publication against non-cooperating POSIX writers."""

import errno
import os
import subprocess
import sys
from pathlib import Path

import pytest

from w3plex.security import EncryptedIOContext
from w3plex.security.memory import ProcessProtection
from w3plex.security.storage import CiphertextFile, StoreChanged, UnsafeStorage
from w3plex.security.vault import Vault

FIXTURES = Path(__file__).parent / "fixtures"
MASTER = "PUBLIC-TEST-vault-create-password"
COLLISION = b"PUBLIC-TEST-non-cooperating-writer"


@pytest.mark.parametrize("operation", ["storage", "vault", "migration-backup"])
def test_exclusive_publication_preserves_a_concurrent_creation(
    tmp_path, monkeypatch, operation
):
    protection = ProcessProtection()
    protection.activate()
    source = tmp_path / "store"
    target = source
    original = (FIXTURES / "legacy-security/ks01-4096.bin").read_bytes()
    if operation == "migration-backup":
        source.write_bytes(original)
        target = source.with_name(source.name + ".legacy.bak")
        owner = EncryptedIOContext(
            protection=protection,
            keystore_path=source,
            input_handler=lambda _: "PUBLIC-TEST-master-password",
        )
    else:
        storage = CiphertextFile(source)
        owner = (
            storage if operation == "storage" else Vault(storage, protection=protection)
        )
    identify = CiphertextFile._target_identity
    created = None

    def raced(storage):
        nonlocal created
        result = identify(storage)
        if (
            storage.path == target
            and result is None
            and list(target.parent.glob("." + target.name + ".*.tmp"))
        ):
            subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "import os, sys; fd = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600); os.write(fd, bytes.fromhex(sys.argv[2])); os.close(fd)",
                    str(target),
                    COLLISION.hex(),
                ],
                check=True,
                capture_output=True,
                timeout=10,
            )
            created = target.stat()
        return result

    monkeypatch.setattr(CiphertextFile, "_target_identity", raced)
    try:
        with pytest.raises(StoreChanged):
            if operation == "storage":
                owner.write(
                    (FIXTURES / "vault-v1/sample.vault").read_bytes(), expected=None
                )
            elif operation == "vault":
                owner.create(MASTER.encode())
            else:
                owner.unlock_keystore()
        assert created is not None
        assert target.stat() == created
        assert target.read_bytes() == COLLISION
        if operation == "migration-backup":
            assert source.read_bytes() == original
        assert not list(tmp_path.glob("*.tmp"))
    finally:
        owner.close()


@pytest.mark.parametrize("point", ["publish", "unlink", "directory-sync"])
def test_exclusive_publication_failure_leaves_only_complete_ciphertext(
    tmp_path, monkeypatch, point
):
    raw = (FIXTURES / "vault-v1/sample.vault").read_bytes()
    destination = tmp_path / "store"
    link, unlink, fsync = os.link, os.unlink, os.fsync
    published = False
    failed = False

    def publish(*args, **kwargs):
        nonlocal published
        if point == "publish":
            raise OSError(errno.EPERM, "PUBLIC-TEST-links-unsupported")
        result = link(*args, **kwargs)
        published = True
        return result

    def remove(*args, **kwargs):
        nonlocal failed
        if point == "unlink" and published and not failed:
            failed = True
            raise OSError("PUBLIC-TEST-unlink-failure")
        return unlink(*args, **kwargs)

    def sync(fd):
        if point == "directory-sync" and published:
            raise OSError("PUBLIC-TEST-directory-sync-failure")
        return fsync(fd)

    monkeypatch.setattr(os, "link", publish)
    monkeypatch.setattr(os, "unlink", remove)
    monkeypatch.setattr(os, "fsync", sync)
    with CiphertextFile(destination) as storage:
        with pytest.raises(OSError):
            storage.write(raw, expected=None)
        if point == "publish":
            assert not destination.exists()
        else:
            assert storage.read()[0] == raw
        assert not list(tmp_path.glob("*.tmp"))


@pytest.mark.parametrize("point", ["before-link", "after-link", "after-unlink"])
def test_process_exit_during_exclusive_publication_keeps_ciphertext_only(
    tmp_path, point
):
    script = """import os, sys
from pathlib import Path
from w3plex.security.storage import CiphertextFile
directory, fixture, point = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
link, unlink = os.link, os.unlink
def publish(*args, **kwargs):
    if point == "before-link":
        os._exit(74)
    result = link(*args, **kwargs)
    if point == "after-link":
        os._exit(74)
    return result
def remove(*args, **kwargs):
    result = unlink(*args, **kwargs)
    if point == "after-unlink":
        os._exit(74)
    return result
os.link, os.unlink = publish, remove
with CiphertextFile(directory / "store") as storage:
    storage.write(fixture.read_bytes(), expected=None)
"""
    fixture = (FIXTURES / "vault-v1/sample.vault").absolute()
    raw = fixture.read_bytes()
    result = subprocess.run(
        [sys.executable, "-c", script, str(tmp_path), str(fixture), point],
        check=False,
        capture_output=True,
        timeout=15,
    )
    assert result.returncode == 74, result.stderr
    target = tmp_path / "store"
    temporaries = list(tmp_path.glob("*.tmp"))
    assert all(path.read_bytes() in (b"", raw) for path in tmp_path.iterdir())
    with CiphertextFile(target) as storage:
        if point == "before-link":
            assert not target.exists() and len(temporaries) == 1
        elif point == "after-link":
            assert target.read_bytes() == raw and len(temporaries) == 1
            with pytest.raises(UnsafeStorage):
                storage.read()
        else:
            assert storage.read()[0] == raw and temporaries == []
        # Explicit trusted recovery removes the abandoned ciphertext name;
        # normal reads must continue rejecting a multiply-linked target.
        for temporary in temporaries:
            temporary.unlink()
        if target.exists():
            assert storage.read()[0] == raw
