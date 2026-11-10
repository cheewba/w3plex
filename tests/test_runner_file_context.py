"""Runner file contexts preserve ordinary reads and own only their defaults."""

import asyncio
import base64
import builtins
import hashlib
import pickle
import threading
from copy import deepcopy

import pytest
from cryptography.fernet import Fernet

from w3plex.runner import Runner
from w3plex.security import EncryptedIOContext, ISecretRef, file_format
from w3plex.security.errors import (
    AuthenticationFailed,
    InteractionRequired,
    InvalidStore,
    PermissionDenied,
)
from w3plex.utils.loader import get_file_opener, using_file_opener

PASSWORD = "PUBLIC-TEST-default-file-password"
MASTER = "PUBLIC-TEST-default-master-password"


def test_default_runner_plain_reads_remain_strings_and_reread_source(
    tmp_path, monkeypatch
):
    store = tmp_path / "unused.vault"
    monkeypatch.setenv("W3PLEX_KEYSTORE", str(store))
    monkeypatch.delenv("W3PLEX_SECRET_STORE", raising=False)
    monkeypatch.setattr(
        "w3plex.security.io.request_password",
        lambda prompt: pytest.fail("Unexpected password"),
    )
    source = tmp_path / "lines.txt"
    source.write_bytes(b"\xef\xbb\xbf# comment\r\n first\rsecond\n")
    opener = builtins.open

    async def check():
        runner = Runner()
        await runner.init(
            {
                "reader": {
                    "__init__": "w3plex.utils.loader:FileLoader",
                    "file": str(source),
                }
            },
            str(tmp_path / "config.yaml"),
        )
        try:
            assert await runner.tree.reader() == ["first", "second"]
            source.write_text("changed\n")
            assert await runner.tree.reader() == ["changed"]
            assert get_file_opener() is None
            assert builtins.open is opener
            assert not store.exists()
        finally:
            await runner.finalize()

    asyncio.run(check())


@pytest.mark.parametrize("kind", ["legacy", "modern"])
@pytest.mark.parametrize("lazy", [False, True])
def test_one_default_opener_reads_plain_and_encrypted_files(
    tmp_path, monkeypatch, kind, lazy
):
    store = tmp_path / "keys.vault"
    monkeypatch.setenv("W3PLEX_KEYSTORE", str(store))
    monkeypatch.delenv("W3PLEX_SECRET_STORE", raising=False)
    passwords = []

    def password(prompt):
        passwords.append(prompt)
        return MASTER if prompt.startswith("Master") else PASSWORD

    monkeypatch.setattr("w3plex.security.io.request_password", password)
    plain = tmp_path / "plain.txt"
    plain.write_text("ordinary\n")
    encrypted = tmp_path / "encrypted.dat"
    value = b"PUBLIC-TEST-captured-line\n"
    if kind == "modern":
        envelope, _ = file_format.seal(value, PASSWORD.encode())
        ciphertext = envelope.serialize()
    else:
        key = base64.urlsafe_b64encode(hashlib.sha256(PASSWORD.encode()).digest())
        ciphertext = b"ENC1" + Fernet(key).encrypt(value)
    encrypted.write_bytes(ciphertext)
    opener = builtins.open

    async def check():
        runner = Runner()
        await runner.init(
            {
                name: {
                    "__init__": "w3plex.utils.loader:FileLoader",
                    "__lazy__": lazy,
                    "file": str(path),
                }
                for name, path in (("plain", plain), ("encrypted", encrypted))
            },
            str(tmp_path / "config.yaml"),
        )
        try:
            plain_reader = await runner.tree.plain() if lazy else runner.tree.plain
            encrypted_reader = (
                await runner.tree.encrypted() if lazy else runner.tree.encrypted
            )
            assert await plain_reader() == ["ordinary"]
            assert passwords == []
            values = await encrypted_reader()
            reference = values[0]
            assert isinstance(reference, ISecretRef)
            assert reference.ref(silent=True) == value.decode().strip()
            assert encrypted.read_bytes() == ciphertext
            assert passwords
            requests = list(passwords)
            encrypted.unlink()
            assert (await encrypted_reader())[0].ref(silent=True) == reference.ref(
                silent=True
            )
            assert passwords == requests
            plain.write_text("updated\n")
            assert await plain_reader() == ["updated"]
            assert deepcopy(reference.parent) is reference.parent
            with pytest.raises(PermissionDenied):
                pickle.dumps(reference.parent)
            with pytest.raises(InteractionRequired):
                reference.ref()
            assert get_file_opener() is None
            assert builtins.open is opener
        finally:
            await runner.finalize()
        with pytest.raises(PermissionDenied):
            reference.ref(silent=True)
        await runner.finalize()
        await runner.init({}, str(tmp_path / "config.yaml"))
        await runner.finalize()

    asyncio.run(check())


def test_finalize_during_default_password_input_prevents_late_capture(
    tmp_path, monkeypatch, protection
):
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()

    def password(request):
        entered.set()
        assert release.wait(5)
        return PASSWORD

    class Context(EncryptedIOContext):
        def decrypt_bytes(self, *args, **kwargs):
            try:
                return super().decrypt_bytes(*args, **kwargs)
            finally:
                finished.set()

    context = Context(protection=protection, input_handler=password)
    monkeypatch.setattr("w3plex.security.file_opener.create_context", lambda: context)
    envelope, _ = file_format.seal(b"PUBLIC-TEST-cancelled\n", PASSWORD.encode())
    source = tmp_path / "encrypted"
    source.write_bytes(envelope.serialize())

    async def check():
        runner = Runner()
        await runner.init(
            {
                "reader": {
                    "__init__": "w3plex.utils.loader:FileLoader",
                    "file": str(source),
                }
            },
            str(tmp_path / "config.yaml"),
        )
        reader = runner.tree.reader
        reading = asyncio.create_task(reader())
        try:
            assert await asyncio.to_thread(entered.wait, 5)
            reading.cancel()
            with pytest.raises(asyncio.CancelledError):
                await reading
            await runner.finalize()
            release.set()
            assert await asyncio.to_thread(finished.wait, 5)
            with pytest.raises(PermissionDenied):
                await reader()
        finally:
            release.set()
            await asyncio.gather(reading, return_exceptions=True)
            await runner.finalize()
            context.close()

    asyncio.run(check())


def test_context_opener_is_borrowed_without_creating_or_closing_default(
    tmp_path, monkeypatch
):
    closed = []

    class Opener:
        def __call__(self, path):
            raise AssertionError("No file read was requested")

        def close(self):
            closed.append(True)

    def unexpected_default():
        raise AssertionError("Inherited opener must take precedence")

    monkeypatch.setattr("w3plex.runner.DefaultFileOpener", unexpected_default)
    opener = Opener()

    async def check():
        runner = Runner()
        with using_file_opener(opener):
            await runner.init({}, str(tmp_path / "config.yaml"))
            assert get_file_opener() is opener
        assert get_file_opener() is None
        await runner.finalize()
        assert closed == []

    asyncio.run(check())


@pytest.mark.parametrize("failure", [ValueError, asyncio.CancelledError])
def test_failed_initialization_closes_owned_opener(tmp_path, monkeypatch, failure):
    closed = []

    class Opener:
        def __call__(self, path):
            raise failure()

        def close(self):
            closed.append(True)

    async def factory():
        raise failure()

    monkeypatch.setattr("w3plex.runner.DefaultFileOpener", Opener)
    monkeypatch.setattr("w3plex.config.config.load_path", lambda path: factory)

    async def check():
        runner = Runner()
        with pytest.raises(failure):
            await runner.init(
                {"value": {"__init__": "fixture:factory"}},
                str(tmp_path / "config.yaml"),
            )
        assert closed == [True]
        assert not runner.is_initialized
        assert get_file_opener() is None

    asyncio.run(check())


@pytest.mark.parametrize("content", [b"W3FILE9bad", b"ENC1invalid", b"W3VAULT1bad"])
def test_default_encrypted_read_failure_never_returns_plain_strings(
    tmp_path, monkeypatch, content
):
    monkeypatch.setenv("W3PLEX_KEYSTORE", str(tmp_path / "keys.vault"))
    monkeypatch.delenv("W3PLEX_SECRET_STORE", raising=False)
    monkeypatch.setattr(
        "w3plex.security.io.request_password",
        lambda prompt: MASTER if prompt.startswith("Master") else PASSWORD,
    )
    source = tmp_path / "encrypted"
    source.write_bytes(content)

    async def check():
        runner = Runner()
        await runner.init(
            {
                "reader": {
                    "__init__": "w3plex.utils.loader:FileLoader",
                    "file": str(source),
                }
            },
            str(tmp_path / "config.yaml"),
        )
        try:
            with pytest.raises((InvalidStore, AuthenticationFailed)):
                await runner.tree.reader()
            assert source.read_bytes() == content
        finally:
            await runner.finalize()

    asyncio.run(check())
