"""One file-key store, automatic migration and ciphertext-only recovery."""

import base64
import hashlib
import json
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from w3plex.security import (
    EncryptedIOContext,
    LegacyContext,
    file_format,
    io as encryption_io,
)
from w3plex.security.errors import (
    AuthenticationFailed,
    PermissionDenied,
)
from w3plex.security.storage import StoreChanged

FIXTURES = Path(__file__).parent / "fixtures/legacy-security"
MODERN = Path(__file__).parent / "fixtures/file-v1"
MANIFEST = json.loads((FIXTURES / "manifest.json").read_text())
MASTER = MANIFEST["master_password"]


def test_context_creation_and_plain_reads_do_not_unlock_or_modify_legacy_store(
    tmp_path,
):
    path = tmp_path / "keystore.bin"
    original = (FIXTURES / "ks01-4096.bin").read_bytes()
    path.write_bytes(original)
    context, requests = owner(path)
    try:
        assert (
            context.decrypt_bytes(b"PUBLIC-TEST-plain", source="plain")
            == b"PUBLIC-TEST-plain"
        )
        assert requests == []
        assert path.read_bytes() == original
        assert list(tmp_path.iterdir()) == [path]
    finally:
        context.close()


def test_explicit_legacy_source_read_preserves_store_without_migration(tmp_path):
    path = tmp_path / "import.bin"
    original = (FIXTURES / "ks01-4096.bin").read_bytes()
    path.write_bytes(original)
    context = EncryptedIOContext(
        legacy_keystore_path=path, input_handler=lambda _: MASTER
    )
    try:
        assert context.decrypt_bytes(
            (FIXTURES / "sample.enc").read_bytes(), source="legacy"
        )
        assert path.read_bytes() == original
        assert list(tmp_path.iterdir()) == [path]
    finally:
        context.close()


def owner(path, *, answers=None):
    requests = []

    def answer(request):
        requests.append(request.kind)
        if answers is not None:
            return answers(request)
        return MASTER if request.kind != "file" else "PUBLIC-TEST-file-v1-password"

    return (
        EncryptedIOContext(
            legacy_keystore_path=path,
            keystore_path=path,
            persist_keys=True,
            input_handler=answer,
        ),
        requests,
    )


@pytest.mark.parametrize("selection", ["explicit", "default"])
def test_first_persistent_enc1_read_creates_one_modern_store(
    tmp_path, monkeypatch, selection
):
    path = tmp_path / "selected"
    requests = []

    def answer(request):
        requests.append(request.kind)
        return MANIFEST["file_password"] if request.kind == "file" else MASTER

    if selection == "default":
        monkeypatch.setenv("W3PLEX_KEYSTORE", str(path))
        monkeypatch.delenv("W3PLEX_SECRET_STORE", raising=False)
        monkeypatch.setattr(encryption_io, "_CONTEXT", None)

        def terminal_answer(prompt):
            kind = (
                "master_confirm"
                if prompt == "Master password confirm: "
                else "master"
                if prompt == "Master password: "
                else "file"
            )
            requests.append(kind)
            return MANIFEST["file_password"] if kind == "file" else MASTER

        monkeypatch.setattr(encryption_io, "request_password", terminal_answer)
        context = encryption_io.default_context()
    else:
        context = EncryptedIOContext(
            keystore_path=path, persist_keys=True, input_handler=answer
        )
    raw = (FIXTURES / "sample.enc").read_bytes()
    expected = bytes.fromhex(MANIFEST["plaintext_hex"])
    try:
        assert context.decrypt_bytes(raw, source="legacy-file") == expected
        saved = path.read_bytes()
        assert saved.startswith(b"W3VAULT1")
        assert requests == ["master", "master_confirm", "file"]
        assert context.decrypt_bytes(raw, source="legacy-file") == expected
        assert path.read_bytes() == saved
        assert requests == ["master", "master_confirm", "file"]
        context.lock()
        requests.clear()
        assert context.decrypt_bytes(raw, source="legacy-file") == expected
        assert requests == ["master"]
        assert path.read_bytes() == saved
        assert [item for item in tmp_path.iterdir() if item.stat().st_size] == [path]
        assert not path.with_name(path.name + ".legacy.bak").exists()
    finally:
        context.close()


@pytest.mark.parametrize(
    ("persist", "ask", "use_keystore"),
    [(False, True, True), (True, False, True), (True, True, False)],
)
def test_enc1_read_without_store_creation_leaves_selected_path_absent(
    tmp_path, persist, ask, use_keystore
):
    path = tmp_path / "selected"
    requests = []
    context = EncryptedIOContext(
        keystore_path=path,
        persist_keys=persist,
        input_handler=lambda request: (
            requests.append(request.kind) or MANIFEST["file_password"]
        ),
    )
    try:
        assert context.decrypt_bytes(
            (FIXTURES / "sample.enc").read_bytes(),
            source="legacy-file",
            password=None if ask else MANIFEST["file_password"],
            use_keystore=use_keystore,
            ask_password=ask,
        ) == bytes.fromhex(MANIFEST["plaintext_hex"])
        assert requests == (["file"] if ask else [])
        assert not path.exists()
        assert list(tmp_path.iterdir()) == []
    finally:
        context.close()


@pytest.mark.parametrize("n", [4096, 8192, 16384, 32768])
def test_migration_reuses_password_and_one_unlock_serves_both_formats(tmp_path, n):
    path = tmp_path / "keystore.bin"
    original = (FIXTURES / f"ks01-{n}.bin").read_bytes()
    path.write_bytes(original)
    context, requests = owner(path)
    try:
        context.unlock_keystore()
        backup = path.with_name(path.name + ".legacy.bak")
        assert backup.read_bytes() == original
        assert path.read_bytes().startswith(b"W3VAULT1")
        assert requests == ["master"]
        legacy_raw = (FIXTURES / "sample.enc").read_bytes()
        expected = bytes.fromhex(MANIFEST["plaintext_hex"])
        assert context.decrypt_bytes(legacy_raw, source="legacy") == expected
        modern_raw = (MODERN / "sample.enc").read_bytes()
        modern_expected = bytes.fromhex(
            json.loads((MODERN / "manifest.json").read_text())["plaintext_hex"]
        )
        assert context.decrypt_bytes(modern_raw, source="modern") == modern_expected
        assert requests == ["master", "file"]
        assert context.decrypt_bytes(legacy_raw, source="legacy") == expected
        assert context.decrypt_bytes(modern_raw, source="modern") == modern_expected
        assert requests == ["master", "file"]
        context.lock()
        requests.clear()
        assert context.decrypt_bytes(modern_raw, source="modern") == modern_expected
        assert context.decrypt_bytes(legacy_raw, source="legacy") == expected
        assert requests == ["master"]
        saved = path.read_bytes()
        context.unlock_keystore()
        assert path.read_bytes() == saved and backup.read_bytes() == original
        for entry in tmp_path.iterdir():
            persisted = entry.read_bytes()
            assert MASTER.encode() not in persisted
            assert bytes.fromhex(MANIFEST["plaintext_hex"]) not in persisted
    finally:
        context.close()


def test_legacy_input_cannot_repopulate_a_locked_migrated_store(tmp_path):
    path = tmp_path / "keystore.bin"
    original = (FIXTURES / "ks01-4096.bin").read_bytes()
    path.write_bytes(original)
    context, _ = owner(path)
    try:
        context.unlock_keystore()
        before = path.read_bytes()
        writer = LegacyContext(None)
        try:
            raw, _ = writer.encrypt_data(
                "PUBLIC-TEST-unregistered",
                password="PUBLIC-TEST-other-file",
                add_to_keystore=False,
            )
        finally:
            writer.lock()

        def answer(request):
            context.lock()
            return "PUBLIC-TEST-other-file"

        context._input = answer
        with pytest.raises(PermissionDenied):
            context.decrypt_bytes(base64.b64decode(raw), source="new-legacy")
        assert path.read_bytes() == before and context._keys == {}
    finally:
        context.close()


@pytest.mark.parametrize("point", ["before", "after"])
def test_real_process_exit_leaves_a_recoverable_store_and_backup(tmp_path, point):
    path = tmp_path / "keystore.bin"
    original = (FIXTURES / "ks01-4096.bin").read_bytes()
    path.write_bytes(original)
    script = """import os,sys
from w3plex.security import EncryptedIOContext
context = EncryptedIOContext(keystore_path=sys.argv[1], input_handler=lambda _: "PUBLIC-TEST-master-password")
replace = os.replace
def crash(source, destination, **kwargs):
    if destination == "keystore.bin":
        if sys.argv[2] == "after":
            replace(source, destination, **kwargs)
        os._exit(42)
    return replace(source, destination, **kwargs)
os.replace = crash
context.unlock_keystore()
raise AssertionError("Crash point not reached")
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", script, str(path), point],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 42, result.stderr
    assert path.with_name(path.name + ".legacy.bak").read_bytes() == original
    for entry in tmp_path.iterdir():
        assert MASTER.encode() not in entry.read_bytes()
        assert (
            hashlib.sha256(MANIFEST["file_password"].encode()).digest()
            not in entry.read_bytes()
        )
    context, _ = owner(path)
    try:
        context.unlock_keystore()
        assert context.decrypt_bytes(
            (FIXTURES / "sample.enc").read_bytes(), source="legacy"
        )
    finally:
        context.close()


def test_cli_encrypted_read_migrates_one_path_and_unlocks_once(tmp_path):
    path = tmp_path / "keystore.bin"
    path.write_bytes((FIXTURES / "ks01-4096.bin").read_bytes())
    script = """import builtins,getpass,os,sys
from pathlib import Path
os.environ["W3PLEX_KEYSTORE"] = sys.argv[1]
os.environ.pop("W3PLEX_SECRET_STORE", None)
sys.stdin.isatty = lambda: True
prompts = []
getpass.getpass = lambda prompt: prompts.append(prompt) or "PUBLIC-TEST-master-password"
builtins.input = lambda _: (_ for _ in ()).throw(AssertionError("Unexpected migration dialog"))
from w3plex.main import process_args
process_args(["decrypt", sys.argv[2], "--output", "legacy.dec", "--keystore"])
from w3plex.security import encrypt_file
with open(sys.argv[2], "rb") as stream:
    assert stream.read()
source = Path("modern.txt")
source.write_text("PUBLIC-TEST-modern")
encrypted = encrypt_file(source, password="PUBLIC-TEST-file", add_to_keystore=True)
with open(encrypted) as stream:
    assert stream.read() == "PUBLIC-TEST-modern"
assert prompts == ["Master password: "]
assert Path(sys.argv[1]).read_bytes().startswith(b"W3VAULT1")
assert not Path("private").exists()
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", script, str(path), str(FIXTURES / "sample.enc")],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert "PUBLIC-TEST-master-password" not in result.stdout + result.stderr


def test_noninteractive_cli_unlock_does_not_fall_back_to_input(tmp_path):
    path = tmp_path / "keystore.bin"
    original = (FIXTURES / "ks01-4096.bin").read_bytes()
    path.write_bytes(original)
    script = """import builtins,getpass,os,sys
os.environ["W3PLEX_KEYSTORE"] = sys.argv[1]
os.environ.pop("W3PLEX_SECRET_STORE", None)
sys.stdin.isatty = lambda: False
def unexpected(*args):
    raise AssertionError("Ordinary or secret input attempted without a TTY")
builtins.input = getpass.getpass = unexpected
from w3plex.main import main
sys.argv = ["w3plex", "decrypt", sys.argv[2], "--keystore", "--output", "legacy.dec"]
main()
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", script, str(path), str(FIXTURES / "sample.enc")],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 1 and "interaction_required" in result.stderr
    assert path.read_bytes() == original
    assert not path.with_name(path.name + ".legacy.bak").exists()


@pytest.mark.parametrize("selection", ["default", "old", "alias", "same", "conflict"])
def test_default_context_selects_one_path_without_creating_files(tmp_path, selection):
    script = """import os,sys
from pathlib import Path
os.environ.pop("W3PLEX_KEYSTORE", None)
os.environ.pop("W3PLEX_SECRET_STORE", None)
selected = Path(sys.argv[1]) / "selected"
mode = sys.argv[2]
if mode in {"old", "same", "conflict"}:
    os.environ["W3PLEX_KEYSTORE"] = str(selected)
if mode in {"alias", "same", "conflict"}:
    os.environ["W3PLEX_SECRET_STORE"] = str(selected if mode != "conflict" else selected.with_name("other"))
from w3plex.security.io import default_context
if mode == "conflict":
    try:
        default_context()
    except ValueError:
        pass
    else:
        raise AssertionError("Different active paths were accepted")
else:
    context = default_context()
    expected = Path.home() / ".keystore.bin" if mode == "default" else selected
    assert context._keystore_path == context._legacy.path == expected
    context.close()
assert not list(Path(sys.argv[1]).iterdir())
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", script, str(tmp_path), selection],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    "alias", ["source-symlink", "backup-symlink", "backup-hardlink"]
)
def test_migration_rejects_path_aliases_without_touching_other_files(tmp_path, alias):
    path = tmp_path / "keystore.bin"
    original = (FIXTURES / "ks01-4096.bin").read_bytes()
    target = tmp_path / "target"
    target.write_bytes(original)
    backup = path.with_name(path.name + ".legacy.bak")
    if alias == "source-symlink":
        path.symlink_to(target)
    else:
        path.write_bytes(original)
        if alias == "backup-symlink":
            backup.symlink_to(target)
        else:
            os.link(target, backup)
    context, _ = owner(path)
    try:
        from w3plex.security.errors import SecurityError

        with pytest.raises(SecurityError):
            context.unlock_keystore()
        assert path.read_bytes() == target.read_bytes() == original
    finally:
        context.close()


@pytest.mark.parametrize("failure", ["cancel", "password", "source-change", "lock"])
def test_unlock_failures_never_replace_the_selected_source(tmp_path, failure):
    path = tmp_path / "keystore.bin"
    original = (FIXTURES / "ks01-4096.bin").read_bytes()
    path.write_bytes(original)

    def answer(_):
        if failure == "cancel":
            raise KeyboardInterrupt()
        if failure == "source-change":
            path.write_bytes(original + b"changed")
        if failure == "lock":
            context.lock()
        return "PUBLIC-TEST-wrong" if failure == "password" else MASTER

    context, requests = owner(path, answers=answer)
    try:
        expected = {
            "cancel": KeyboardInterrupt,
            "password": AuthenticationFailed,
            "source-change": StoreChanged,
            "lock": PermissionDenied,
        }[failure]
        with pytest.raises(expected) as raised:
            context.unlock_keystore()
        assert MASTER not in str(raised.value)
        assert path.read_bytes() == original + (
            b"changed" if failure == "source-change" else b""
        )
        assert not path.with_name(path.name + ".legacy.bak").exists()
        assert requests == ["master"]
    finally:
        context.close()


@pytest.mark.parametrize("kind", ["legacy", "modern"])
def test_encrypted_read_automatically_migrates_without_creating_another_store(
    tmp_path, kind
):
    path = tmp_path / "keystore.bin"
    original = (FIXTURES / "ks01-4096.bin").read_bytes()
    path.write_bytes(original)
    context, requests = owner(path)
    try:
        fixture = FIXTURES if kind == "legacy" else MODERN
        source = tmp_path / "input.enc"
        raw = (fixture / "sample.enc").read_bytes()
        source.write_bytes(raw)
        context.enable()
        try:
            with open(source, "rb") as stream:
                assert stream.read()
        finally:
            context.disable()
        assert path.read_bytes().startswith(b"W3VAULT1")
        backup = path.with_name(path.name + ".legacy.bak")
        assert backup.read_bytes() == original
        assert source.read_bytes() == raw
        assert {p for p in tmp_path.iterdir() if not p.name.endswith(".lock")} == {
            path,
            backup,
            source,
        }
        assert requests == (["master"] if kind == "legacy" else ["master", "file"])
    finally:
        context.close()


def test_plaintext_legacy_backup_is_encrypted_and_recoverable(tmp_path):
    path = tmp_path / "keystore.bin"
    key = hashlib.sha256(MANIFEST["file_password"].encode()).digest()
    original = (
        bytes(16) + json.dumps({"keys": [base64.b64encode(key).decode()]}).encode()
    )
    path.write_bytes(original)
    context, requests = owner(path)
    try:
        context.unlock_keystore()
        assert requests == ["master", "master_confirm"]
        backup = path.with_name(path.name + ".legacy.bak").read_bytes()
        parsed = file_format.parse(backup)
        assert (
            file_format.open_payload(
                parsed, file_format.unwrap(parsed, MASTER.encode())
            )
            == original
        )
        assert key not in backup and base64.b64encode(key) not in backup
        assert context.decrypt_bytes(
            (FIXTURES / "sample.enc").read_bytes(), source="legacy"
        )
    finally:
        context.close()


def test_conflicting_backup_is_preserved(tmp_path):
    path = tmp_path / "keystore.bin"
    original = (FIXTURES / "ks01-4096.bin").read_bytes()
    path.write_bytes(original)
    backup = path.with_name(path.name + ".legacy.bak")
    backup.write_bytes(b"PUBLIC-TEST-unrelated-backup")
    context, _ = owner(path)
    try:
        with pytest.raises(StoreChanged):
            context.unlock_keystore()
        assert path.read_bytes() == original
        assert backup.read_bytes() == b"PUBLIC-TEST-unrelated-backup"
    finally:
        context.close()


@pytest.mark.parametrize("point", ["before-source-replace", "after-source-replace"])
def test_interrupted_replacement_can_be_retried_without_losing_originals(
    tmp_path, monkeypatch, point
):
    path = tmp_path / "keystore.bin"
    original = (FIXTURES / "ks01-4096.bin").read_bytes()
    path.write_bytes(original)
    context, _ = owner(path)
    replace = os.replace

    def interrupt(source, target, **kwargs):
        if target == path.name:
            if point == "after-source-replace":
                replace(source, target, **kwargs)
            raise OSError("PUBLIC-TEST-interruption")
        return replace(source, target, **kwargs)

    try:
        with monkeypatch.context() as patch:
            patch.setattr(os, "replace", interrupt)
            from w3plex.security.errors import SecurityError

            with pytest.raises(SecurityError):
                context.unlock_keystore()
        assert path.with_name(path.name + ".legacy.bak").read_bytes() == original
        assert (
            path.read_bytes() == original
            if point == "before-source-replace"
            else path.read_bytes().startswith(b"W3VAULT1")
        )
        context.unlock_keystore()
        assert context.decrypt_bytes(
            (FIXTURES / "sample.enc").read_bytes(), source="legacy"
        )
        assert not list(tmp_path.glob("*.tmp"))
    finally:
        context.close()


def test_lock_from_another_thread_cancels_pending_migration(tmp_path):
    path = tmp_path / "keystore.bin"
    original = (FIXTURES / "ks01-4096.bin").read_bytes()
    path.write_bytes(original)

    def answer(_):
        worker = threading.Thread(target=context.lock)
        worker.start()
        worker.join(timeout=2)
        assert not worker.is_alive(), (
            "Private input prevented another thread from locking"
        )
        return MASTER

    context, requests = owner(path, answers=answer)
    try:
        with pytest.raises(PermissionDenied):
            context.unlock_keystore()
        assert requests == ["master"]
        assert path.read_bytes() == original
        assert not path.with_name(path.name + ".legacy.bak").exists()
        assert context._keystore is None
    finally:
        context.close()
