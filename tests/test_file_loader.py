"""File loading, line filters, saved references and synchronous openers."""

import asyncio
import base64
import hashlib
import threading
from dataclasses import dataclass

import pytest
from cryptography.fernet import Fernet
from eth_account import Account as EthAccount
from w3ext import Account

from w3plex.security.errors import PermissionDenied, SecurityError
from w3plex.security.legacy import LegacyContext
from w3plex.utils.loader import (
    FileLoader,
    accounts_loader,
    get_file_opener,
    using_file_opener,
    wallets_loader,
)


@dataclass
class Reference:
    value: bytes

    def ref(self, *, silent=False):
        return self.value


def reveal(values):
    return [value.ref(silent=True) for value in values]


def test_sync_opener_runs_in_worker_and_reuses_capture_across_loops():
    calls = []
    owner = threading.get_ident()

    def opener(path):
        calls.append(threading.get_ident())
        with pytest.raises(RuntimeError):
            asyncio.get_running_loop()
        return Reference(b"first\n")

    with using_file_opener(opener):
        reader = FileLoader(file="unused")
    assert reveal(asyncio.run(reader())) == ["first"]
    assert reveal(asyncio.run(reader())) == ["first"]
    assert len(calls) == 1
    assert calls[0] != owner


def test_nested_sync_contexts_and_reference_precedence(tmp_path):
    path = tmp_path / "data.txt"
    path.write_text("plain\n")
    outer = lambda path: Reference(b"outer\n")
    nested = lambda path: Reference(b"nested\n")
    with using_file_opener(outer):
        inherited = FileLoader(file=path)
        with using_file_opener(nested):
            overridden = FileLoader(file=path)
            existing = FileLoader(file=Reference(b"reference\n"))
        with using_file_opener(None):
            plain = FileLoader(file=path)
        assert get_file_opener() is outer
    assert get_file_opener() is None
    assert reveal(asyncio.run(inherited())) == ["outer"]
    assert reveal(asyncio.run(overridden())) == ["nested"]
    assert asyncio.run(plain()) == ["plain"]
    assert reveal(asyncio.run(existing())) == ["reference"]


def test_sync_failure_retries_without_partial_cache():
    calls = []

    def opener(path):
        calls.append(path)
        if len(calls) == 1:
            raise PermissionDenied()
        return Reference(b"recovered\n")

    with using_file_opener(opener):
        reader = FileLoader(file="unused")
    with pytest.raises(PermissionDenied):
        asyncio.run(reader())
    assert reveal(asyncio.run(reader())) == ["recovered"]
    assert len(calls) == 2


def test_cancelled_sync_wait_does_not_cancel_worker_capture():
    entered = threading.Event()
    release = threading.Event()
    calls = []

    def opener(path):
        calls.append(path)
        entered.set()
        assert release.wait(5)
        return Reference(b"captured\n")

    with using_file_opener(opener):
        reader = FileLoader(file="unused")

    async def check():
        task = asyncio.create_task(reader())
        try:
            assert await asyncio.to_thread(entered.wait, 5)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        finally:
            release.set()
        assert reveal(await reader()) == ["captured"]

    asyncio.run(check())
    assert len(calls) == 1


@pytest.mark.parametrize("protected", [False, True])
def test_line_filters_offsets_and_transform_hook(tmp_path, protected):
    raw = b"\xef\xbb\xbf # comment\r\n \xc3\xa9clair \r\n skip\r two\n\n"
    path = tmp_path / "data.txt"
    path.write_bytes(raw)
    seen = []

    class Reader(FileLoader):
        def process_line(self, line, fn):
            seen.append(line)
            return fn(line)

    reader = Reader(
        file=Reference(raw) if protected else path,
        filter=r" (?:éclair|two)",
    )
    result = asyncio.run(reader.process(lambda value: value))
    assert result == seen
    assert (reveal(result) if protected else result) == ["éclair", "two"]
    if not protected:
        assert asyncio.run(reader.process(len)) == [6, 3]
    assert asyncio.run(reader.process(lambda _: None)) == []


def test_accounts_loader_stays_callable_and_captures_only_on_call():
    calls = []

    def opener(path):
        calls.append(path)
        return Reference(("11" * 32 + "\n").encode())

    with using_file_opener(opener):
        reader = accounts_loader(file="unused")
    assert callable(reader)
    assert calls == []
    first = asyncio.run(reader())[0]
    second = asyncio.run(reader())[0]
    assert first.address == second.address
    assert calls == ["unused"]


def test_existing_reader_captures_once_across_concurrent_reads_and_lock(
    vault, vault_password, secret_store, tmp_path
):
    data = tmp_path / "data.txt"
    data.write_text("original\n")
    calls = []

    def opener(path):
        calls.append(path)
        return secret_store.capture_file(path)

    with using_file_opener(opener):
        reader = FileLoader(file=data)

    async def read():
        first, second = await asyncio.gather(reader(), reader())
        assert first[0].parent.identifier == second[0].parent.identifier
        return first

    values = asyncio.run(read())
    assert calls == [data]
    data.write_text("changed\n")
    assert asyncio.run(reader())[0].ref(silent=True) == "original"
    vault.lock()
    with pytest.raises(PermissionDenied):
        asyncio.run(reader())
    data.unlink()
    vault.unlock(vault_password)
    assert asyncio.run(reader())[0].ref(silent=True) == "original"
    assert values[0].ref(silent=True) == "original"
    assert calls == [data]


def test_protected_opener_failure_never_falls_back_to_plain_read(tmp_path):
    data = tmp_path / "data.txt"
    data.write_text("PUBLIC-TEST-private-line\n")

    def denied(path):
        raise PermissionDenied()

    with using_file_opener(denied):
        reader = FileLoader(file=data)
    with pytest.raises(PermissionDenied):
        asyncio.run(reader())


@pytest.mark.parametrize("failure", ["wrong-result", "private-error"])
def test_bad_protected_opener_returns_a_safe_error(tmp_path, failure):
    secret = "PUBLIC-TEST-opener-private-content"

    def opener(path):
        if failure == "private-error":
            raise RuntimeError(secret)
        return secret

    with using_file_opener(opener):
        reader = FileLoader(file=tmp_path / "data.txt")
    with pytest.raises(SecurityError) as caught:
        asyncio.run(reader())
    assert secret not in str(caught.value)
    assert caught.value.__context__ is None
    assert caught.value.__cause__ is None


def test_transform_error_and_missing_file_are_not_hidden(tmp_path):
    source = tmp_path / "lines.txt"
    source.write_text("bad integer\n")
    with pytest.raises(ValueError):
        asyncio.run(FileLoader(file=str(source)).process(int))
    with pytest.raises(FileNotFoundError):
        asyncio.run(FileLoader(file=str(tmp_path / "missing")).process())


def test_accounts_and_wallets_loader_keep_legacy_types(tmp_path):
    source = tmp_path / "keys.txt"
    source.write_text("01" * 32 + "\n")
    accounts = asyncio.run(accounts_loader(file=str(source))())
    assert type(accounts[0]) is Account
    assert accounts[0].address == EthAccount.from_key("01" * 32).address
    assert accounts[0].key.hex() == "01" * 32
    source.write_text(accounts[0].address.lower() + "\n")
    assert asyncio.run(wallets_loader(file=str(source))) == [accounts[0].address]


def test_enc1_is_captured_once_without_modifying_original(
    vault, vault_password, secret_store, tmp_path
):
    password = "PUBLIC-TEST-legacy-password"
    key = base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())
    encrypted = b"ENC1" + Fernet(key).encrypt(b"one\ntwo\n")
    filename = tmp_path / "legacy.enc"
    filename.write_bytes(encrypted)
    legacy = LegacyContext(None, input_handler=lambda request: password)
    captured = secret_store.capture_file(filename, context=legacy)
    assert filename.read_bytes() == encrypted
    values = asyncio.run(FileLoader(file=captured).process())
    filename.unlink()
    legacy.lock()
    vault.lock()
    vault.unlock(vault_password)
    assert [value.ref(silent=True) for value in values] == ["one", "two"]
