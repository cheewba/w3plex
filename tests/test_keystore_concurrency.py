"""One context serializes master unlock while lock can revoke private input."""

import json
import threading
from pathlib import Path

import pytest

from w3plex.security import EncryptedIOContext
from w3plex.security.errors import PermissionDenied

FIXTURES = Path(__file__).parent / "fixtures"
MASTER = "PUBLIC-TEST-concurrent-master"


@pytest.mark.parametrize("existing", [False, True])
@pytest.mark.parametrize("format_name", ["modern", "legacy"])
def test_concurrent_encrypted_reads_share_one_master_unlock(
    tmp_path, existing, format_name
):
    directory = FIXTURES / ("file-v1" if format_name == "modern" else "legacy-security")
    manifest = json.loads((directory / "manifest.json").read_text())
    file_password = manifest["password" if format_name == "modern" else "file_password"]
    path = tmp_path / "selected"
    master = MASTER
    if existing:
        path.write_bytes((FIXTURES / "security/vault-v1.bin").read_bytes())
        master = json.loads((FIXTURES / "security/vault-v1.json").read_text())[
            "password"
        ]
    start, overlap = threading.Barrier(2), threading.Barrier(2)
    requests, results, errors = [], [], []

    def answer(request):
        requests.append(request.kind)
        if request.kind == ("master" if existing else "master_confirm"):
            try:
                overlap.wait(timeout=0.25)
            except threading.BrokenBarrierError:
                pass
        return file_password if request.kind == "file" else master

    owner = EncryptedIOContext(
        keystore_path=path, persist_keys=True, input_handler=answer
    )
    raw = (directory / "sample.enc").read_bytes()

    def read():
        try:
            start.wait(timeout=3)
            results.append(owner.decrypt_bytes(raw, source="sample"))
        except BaseException as exc:
            errors.append(exc)

    workers = [threading.Thread(target=read, daemon=True) for _ in range(2)]
    try:
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=10)
        assert all(not worker.is_alive() for worker in workers)
        assert errors == []
        assert results == [bytes.fromhex(manifest["plaintext_hex"])] * 2
        assert requests.count("master") == 1
        assert requests.count("master_confirm") == (0 if existing else 1)
        assert path.read_bytes().startswith(b"W3VAULT1")
        assert not path.with_name(path.name + ".legacy.bak").exists()
    finally:
        owner.close()


@pytest.mark.parametrize("prompt", ["master", "master_confirm"])
def test_lock_interrupts_keystore_input_from_another_thread(tmp_path, prompt):
    path = tmp_path / "selected"
    completed = threading.Event()
    pending, workers, requests = [], [], []

    def lock():
        owner.lock()
        completed.set()

    def answer(request):
        requests.append(request.kind)
        if request.kind == prompt:
            worker = threading.Thread(target=lock, daemon=True)
            workers.append(worker)
            worker.start()
            pending.append(completed.wait(timeout=0.25))
        return MASTER

    owner = EncryptedIOContext(keystore_path=path, input_handler=answer)
    try:
        with pytest.raises(PermissionDenied):
            owner.unlock_keystore()
        assert pending == [True]
        assert requests == (
            ["master"] if prompt == "master" else ["master", "master_confirm"]
        )
        assert not path.exists()
    finally:
        for worker in workers:
            worker.join(timeout=3)
            assert not worker.is_alive()
        owner.close()


def test_lock_revokes_queued_unlock_without_starting_another_dialog(
    tmp_path, monkeypatch
):
    path = tmp_path / "selected"
    pending, resume, queued = threading.Event(), threading.Event(), threading.Event()
    requests, errors = [], []
    generation = EncryptedIOContext.generation

    def checkpoint(context):
        epoch = generation.fget(context)
        if threading.current_thread().name == "queued-unlock":
            queued.set()
        return epoch

    monkeypatch.setattr(EncryptedIOContext, "generation", property(checkpoint))

    def answer(request):
        requests.append(request.kind)
        pending.set()
        assert resume.wait(timeout=5)
        return MASTER

    owner = EncryptedIOContext(keystore_path=path, input_handler=answer)

    def unlock():
        try:
            owner.unlock_keystore()
        except BaseException as exc:
            errors.append(exc)

    first = threading.Thread(target=unlock, daemon=True)
    second = threading.Thread(target=unlock, name="queued-unlock", daemon=True)
    try:
        first.start()
        assert pending.wait(timeout=3)
        second.start()
        assert queued.wait(timeout=3)
        owner.lock()
        resume.set()
        first.join(timeout=5)
        second.join(timeout=5)
        assert not first.is_alive() and not second.is_alive()
        assert len(errors) == 2 and all(
            type(error) is PermissionDenied for error in errors
        )
        assert requests == ["master"]
        assert not path.exists()
    finally:
        resume.set()
        first.join(timeout=5)
        if second.ident is not None:
            second.join(timeout=5)
        owner.close()
