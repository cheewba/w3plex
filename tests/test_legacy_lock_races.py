"""Legacy input cannot restore keys after its operation has been locked."""

import base64
import json
import os
import threading
from pathlib import Path

import pytest

from w3plex.security import EncryptedIOContext, LegacyContext
from w3plex.security.errors import PermissionDenied

FIXTURES = Path(__file__).parent / "fixtures/legacy-security"
MANIFEST = json.loads((FIXTURES / "manifest.json").read_text())


@pytest.mark.parametrize("mixed_formats", [False, True])
def test_concurrent_legacy_reads_reuse_one_master_unlock(tmp_path, mixed_formats):
    path = tmp_path / "legacy-store"
    original = (FIXTURES / "ks01-4096.bin").read_bytes()
    path.write_bytes(original)
    requests, results, errors = [], [], []
    gate = threading.Barrier(4)

    def answer(request):
        requests.append(request.kind)
        return MANIFEST["master_password"]

    context = (
        EncryptedIOContext(legacy_keystore_path=path, input_handler=answer)
        if mixed_formats
        else LegacyContext(path, input_handler=answer)
    )
    raw = (FIXTURES / "sample.enc").read_bytes()

    def read():
        try:
            gate.wait(timeout=3)
            results.append(context.decrypt_bytes(raw, source="legacy-file"))
        except BaseException as exc:
            errors.append(exc)

    workers = [threading.Thread(target=read, daemon=True) for _ in range(4)]
    try:
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=5)
        assert all(not worker.is_alive() for worker in workers)
        assert errors == []
        assert results == [bytes.fromhex(MANIFEST["plaintext_hex"])] * 4
        assert requests == ["master"] and path.read_bytes() == original
    finally:
        context.close() if mixed_formats else context.lock()


@pytest.mark.parametrize("mixed_formats", [False, True])
@pytest.mark.parametrize("prompt", ["file", "master", "master_confirm"])
def test_legacy_private_input_does_not_block_lock_from_another_thread(
    tmp_path, mixed_formats, prompt
):
    path = tmp_path / "legacy-store"
    original = (FIXTURES / "ks01-4096.bin").read_bytes() if prompt == "master" else None
    if original is not None:
        path.write_bytes(original)
    persist = prompt == "master_confirm"
    completed, started = threading.Event(), threading.Event()
    pending, workers, errors = [], [], []

    def lock():
        started.set()
        try:
            context.lock()
        except BaseException as exc:
            errors.append(exc)
        finally:
            completed.set()

    def answer(request):
        if request.kind == prompt:
            worker = threading.Thread(target=lock, daemon=True)
            workers.append(worker)
            worker.start()
            assert started.wait(timeout=3)
            pending.append(completed.wait(timeout=0.25))
        return MANIFEST[
            "file_password" if request.kind == "file" else "master_password"
        ]

    context = (
        EncryptedIOContext(
            legacy_keystore_path=path,
            persist_legacy_keys=persist,
            input_handler=answer,
        )
        if mixed_formats
        else LegacyContext(path, persist_keys=persist, input_handler=answer)
    )
    try:
        with pytest.raises(PermissionDenied):
            context.decrypt_bytes(
                (FIXTURES / "sample.enc").read_bytes(), source="legacy-file"
            )
        assert pending == [True], "Private input blocked session lock"
        assert errors == []
        assert (path.read_bytes() if path.exists() else None) == original
        legacy = context._legacy if mixed_formats else context
        assert legacy._keys is None and legacy._master_key is None
    finally:
        for worker in workers:
            worker.join(timeout=3)
            assert not worker.is_alive()
        context.close() if mixed_formats else context.lock()


@pytest.mark.parametrize("mixed_formats", [False, True])
@pytest.mark.parametrize("persist", [False, True])
def test_stale_file_password_cannot_be_cached_or_persisted(
    tmp_path, mixed_formats, persist
):
    path = tmp_path / "legacy-store"
    requests = []

    def answer(request):
        requests.append(request.kind)
        if request.kind == "file" and requests.count("file") == 1:
            context.lock()
        return MANIFEST[
            "file_password" if request.kind == "file" else "master_password"
        ]

    context = (
        EncryptedIOContext(
            legacy_keystore_path=path,
            persist_legacy_keys=persist,
            input_handler=answer,
        )
        if mixed_formats
        else LegacyContext(path, persist_keys=persist, input_handler=answer)
    )
    raw = (FIXTURES / "sample.enc").read_bytes()
    try:
        with pytest.raises(PermissionDenied):
            context.decrypt_bytes(raw, source="legacy-file")
        assert not path.exists()
        assert requests == ["file"]
        assert context.decrypt_bytes(raw, source="legacy-file") == bytes.fromhex(
            MANIFEST["plaintext_hex"]
        )
        assert requests.count("file") == 2
        assert path.exists() is persist
    finally:
        if mixed_formats:
            context.close()
        else:
            context.lock()


@pytest.mark.parametrize("mixed_formats", [False, True])
def test_stale_master_password_cannot_restore_legacy_keys(tmp_path, mixed_formats):
    path = tmp_path / "legacy-store"
    original = (FIXTURES / "ks01-4096.bin").read_bytes()
    path.write_bytes(original)
    requests = []

    def answer(request):
        requests.append(request.kind)
        if len(requests) == 1:
            context.lock()
        return MANIFEST["master_password"]

    context = (
        EncryptedIOContext(legacy_keystore_path=path, input_handler=answer)
        if mixed_formats
        else LegacyContext(path, input_handler=answer)
    )
    raw = (FIXTURES / "sample.enc").read_bytes()
    try:
        with pytest.raises(PermissionDenied):
            context.decrypt_bytes(raw, source="legacy-file")
        assert path.read_bytes() == original
        assert context.decrypt_bytes(raw, source="legacy-file") == bytes.fromhex(
            MANIFEST["plaintext_hex"]
        )
        assert requests == ["master", "master"]
        assert path.read_bytes() == original
    finally:
        if mixed_formats:
            context.close()
        else:
            context.lock()


def test_lock_before_legacy_store_commit_preserves_original(tmp_path, monkeypatch):
    path = tmp_path / "legacy-store"
    original = (FIXTURES / "ks01-4096.bin").read_bytes()
    path.write_bytes(original)
    password = "PUBLIC-TEST-unregistered-file"
    writer = LegacyContext(None)
    encoded, _ = writer.encrypt_data(
        "PUBLIC-TEST-new-data", password=password, add_to_keystore=False
    )
    writer.lock()
    context = LegacyContext(
        path,
        persist_keys=True,
        input_handler=lambda request: (
            password if request.kind == "file" else MANIFEST["master_password"]
        ),
    )
    sync = os.fsync

    def lock_after_sync(descriptor):
        sync(descriptor)
        context.lock()

    monkeypatch.setattr(os, "fsync", lock_after_sync)
    try:
        with pytest.raises(PermissionDenied):
            context.decrypt_bytes(base64.b64decode(encoded), source="legacy-file")
        assert path.read_bytes() == original
        assert list(tmp_path.iterdir()) == [path]
    finally:
        context.lock()
