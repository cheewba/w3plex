"""Real POSIX persistence, owner access and ciphertext-only crash artifacts."""

import errno
import os
import stat
import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock

import pytest

from w3plex.security import vault_format as codec
from w3plex.security.errors import UnsupportedProtection
from w3plex.security.storage import (
    CiphertextFile,
    StoreChanged,
    UnsafeStorage,
    WriterBusy,
)

FIXTURES = Path(__file__).parent / "fixtures/vault-v1"


@pytest.fixture
def store(tmp_path):
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    with CiphertextFile(directory / "vault") as storage:
        yield storage


def ciphertexts():
    old = (FIXTURES / "sample.vault").read_bytes()
    envelope = codec.parse(old)
    new = codec.update_payload(
        envelope, bytes(range(32)), b'{"records":[]}'
    ).serialize()
    return old, new


def test_mode_and_ciphertext_checked_before_first_write(store, monkeypatch):
    old, _ = ciphertexts()
    observed = []
    fdopen = os.fdopen

    def inspect(fd, mode, *args, **kwargs):
        if mode == "wb":
            info = os.fstat(fd)
            observed.append((stat.S_IMODE(info.st_mode), info.st_size))
        return fdopen(fd, mode, *args, **kwargs)

    monkeypatch.setattr(os, "fdopen", inspect)
    store.write(old, expected=None)
    assert observed == [(0o600, 0)]
    for path in store.path.parent.iterdir():
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert b"PUBLIC-TEST-v1-password" not in path.read_bytes()
    assert store.path.read_bytes() == old


@pytest.mark.parametrize("point", ["file-sync", "replace", "directory-sync"])
def test_write_failure_leaves_complete_old_or_new_store(store, monkeypatch, point):
    old, new = ciphertexts()
    expected = store.write(old, expected=None)
    fsync = os.fsync
    calls = 0

    def sync(fd):
        nonlocal calls
        calls += 1
        if (point == "file-sync" and calls == 1) or (
            point == "directory-sync" and calls == 2
        ):
            raise OSError("PUBLIC-TEST-sync-failure")
        return fsync(fd)

    def replace(*args, **kwargs):
        raise OSError("PUBLIC-TEST-replace-failure")

    monkeypatch.setattr(os, "fsync", sync)
    if point == "replace":
        monkeypatch.setattr(os, "replace", replace)
    with pytest.raises(OSError):
        store.write(new, expected=expected)
    remaining = store.read()[0]
    assert remaining == (new if point == "directory-sync" else old)
    codec.open_payload(codec.parse(remaining), bytes(range(32)))
    assert not list(store.path.parent.glob("*.tmp"))


def test_restore_mtime_cannot_hide_a_changed_target(store):
    old, new = ciphertexts()
    expected = store.write(old, expected=None)
    before = store.path.stat()
    store.path.write_bytes(old)
    os.utime(store.path, ns=(before.st_atime_ns, before.st_mtime_ns))
    with pytest.raises(StoreChanged):
        store.write(new, expected=expected)
    assert store.path.read_bytes() == old


def test_temporary_name_substitution_is_detected_before_replace(store, monkeypatch):
    old, new = ciphertexts()
    expected = store.write(old, expected=None)
    fsync = os.fsync
    changed = False

    def substitute(fd):
        nonlocal changed
        if not changed:
            changed = True
            path = next(store.path.parent.glob("*.tmp"))
            path.unlink()
            path.write_bytes(b"PUBLIC-TEST-substitute")
            path.chmod(0o600)
        return fsync(fd)

    monkeypatch.setattr(os, "fsync", substitute)
    with pytest.raises((StoreChanged, UnsafeStorage)):
        store.write(new, expected=expected)
    assert store.path.read_bytes() == old


def test_target_and_parent_substitution_do_not_modify_new_location(store, monkeypatch):
    old, new = ciphertexts()
    expected = store.write(old, expected=None)
    parent = store.path.parent
    fsync = os.fsync
    changed = False

    def substitute(fd):
        nonlocal changed
        if not changed:
            changed = True
            parent.rename(parent.with_name("moved"))
            parent.mkdir(mode=0o700)
        return fsync(fd)

    monkeypatch.setattr(os, "fsync", substitute)
    with pytest.raises(UnsafeStorage):
        store.write(new, expected=expected)
    assert not list(parent.iterdir())
    assert (parent.with_name("moved") / "vault").read_bytes() == old


def test_other_process_cannot_write_while_lock_is_held(store):
    old, new = ciphertexts()
    expected = store.write(old, expected=None)
    script = """import sys
from w3plex.security.storage import CiphertextFile, WriterBusy
with CiphertextFile(sys.argv[1]) as storage:
    before = storage.read()[1]
    try:
        storage.write(b"PUBLIC-TEST-other-writer", expected=before)
    except WriterBusy:
        pass
    else:
        raise AssertionError("Concurrent writer was admitted")
"""
    with store._writer():
        result = subprocess.run(
            [sys.executable, "-I", "-c", script, str(store.path)],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        with pytest.raises(WriterBusy):
            store.write(new, expected=expected)
    assert store.path.read_bytes() == old


@pytest.mark.parametrize(
    "point", ["partial-write", "before-replace", "after-replace", "directory-sync"]
)
def test_process_crash_leaves_ciphertext_only_and_complete_target(
    store, tmp_path, point
):
    old, new = ciphertexts()
    store.write(old, expected=None)
    incoming = tmp_path / "incoming"
    incoming.write_bytes(new)
    incoming.chmod(0o600)
    script = """import os,sys
from pathlib import Path
from w3plex.security.storage import CiphertextFile
point = sys.argv[3]
replace, sync, fdopen = os.replace, os.fsync, os.fdopen
calls = 0
def write_stream(fd, mode, *args, **kwargs):
    if point == "partial-write" and mode == "wb":
        os.write(fd, incoming[:len(incoming)//2])
        os._exit(42)
    return fdopen(fd, mode, *args, **kwargs)
def replace_file(*args, **kwargs):
    if point == "before-replace":
        os._exit(42)
    replace(*args, **kwargs)
    if point == "after-replace":
        os._exit(42)
def sync_file(fd):
    global calls
    calls += 1
    if calls == 2 and point == "directory-sync":
        os._exit(42)
    return sync(fd)
incoming = Path(sys.argv[2]).read_bytes()
os.fdopen, os.replace, os.fsync = write_stream, replace_file, sync_file
with CiphertextFile(sys.argv[1]) as storage:
    storage.write(incoming, expected=storage.read()[1])
raise AssertionError("Crash point was not reached")
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", script, str(store.path), str(incoming), point],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 42, result.stderr
    remaining = store.read()[0]
    assert remaining == (old if point in {"partial-write", "before-replace"} else new)
    codec.open_payload(codec.parse(remaining), bytes(range(32)))
    for path in store.path.parent.iterdir():
        data = path.read_bytes()
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        if path.name.endswith(".tmp"):
            assert new.startswith(data)
        assert b"PUBLIC-TEST-v1-password" not in data
        assert bytes(range(32)) not in data
    # Kernel process teardown must release its writer lock.
    store.write(old, expected=store.read()[1])


@pytest.mark.skipif(sys.platform != "darwin", reason="native macOS extended ACL check")
@pytest.mark.parametrize("target", ["directory", "file"])
def test_mac_extended_acl_is_rejected_even_with_owner_only_mode(store, target):
    old, _ = ciphertexts()
    store.write(old, expected=None)
    path = store.path.parent if target == "directory" else store.path
    expected_mode = 0o700 if target == "directory" else 0o600
    permission = "list,search" if target == "directory" else "read"
    subprocess.run(
        ["/bin/chmod", "+a", f"everyone allow {permission}", str(path)],
        check=True,
        capture_output=True,
    )
    assert stat.S_IMODE(path.stat().st_mode) == expected_mode
    with pytest.raises(UnsafeStorage):
        store.read()


def test_missing_mac_acl_control_is_not_treated_as_no_acl(monkeypatch):
    from w3plex.security import storage

    def unavailable(*args):
        storage.ctypes.set_errno(errno.EIO)

    lib = Mock()
    lib.acl_get_fd_np.side_effect = unavailable
    monkeypatch.setattr(storage.sys, "platform", "darwin")
    monkeypatch.setattr(storage.ctypes, "CDLL", lambda *args, **kwargs: lib)
    with pytest.raises(UnsupportedProtection):
        storage._no_extended_acl(0)
