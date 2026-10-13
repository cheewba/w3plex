"""The existing reader protects snapshots without an alternative read path."""

import asyncio
from copy import deepcopy

import pytest

from w3plex.security import SecretString
from w3plex.security.errors import PermissionDenied, SecurityError
from w3plex.utils.loader import FileLoader

PASSWORD = b"PUBLIC-TEST-snapshot-password"


def test_ordinary_reader_keeps_configuration_deepcopy():
    reader = FileLoader(file="public.txt")
    assert deepcopy(reader).config == reader.config


def test_existing_constructor_reads_a_reference(secret_store):
    source = secret_store.capture(b" # comment\r\n one \r\n two\n")
    reader = FileLoader(file=source)
    values = asyncio.run(reader())
    assert all(isinstance(value, SecretString) for value in values)
    assert [value.ref(silent=True) for value in values] == ["one", "two"]


def test_existing_reader_captures_once_across_concurrent_reads_and_lock(
    secret_store, tmp_path
):
    data = tmp_path / "data.txt"
    data.write_text("original\n")
    calls = []

    def opener(path):
        calls.append(path)
        return secret_store.capture_file(path)

    reader = FileLoader(file=data, opener=opener)

    async def read():
        first, second = await asyncio.gather(reader(), reader())
        assert first[0].parent.identifier == second[0].parent.identifier
        return first

    values = asyncio.run(read())
    assert calls == [data]
    data.write_text("changed\n")
    assert asyncio.run(reader())[0].ref(silent=True) == "original"
    secret_store._vault.lock()
    with pytest.raises(PermissionDenied):
        asyncio.run(reader())
    data.unlink()
    secret_store._vault.unlock(PASSWORD)
    assert asyncio.run(reader())[0].ref(silent=True) == "original"
    assert values[0].ref(silent=True) == "original"
    assert calls == [data]


def test_protected_opener_failure_never_falls_back_to_plain_read(tmp_path):
    data = tmp_path / "data.txt"
    data.write_text("PUBLIC-TEST-private-line\n")

    def denied(path):
        raise PermissionDenied()

    with pytest.raises(PermissionDenied):
        asyncio.run(FileLoader(file=data, opener=denied)())


@pytest.mark.parametrize("failure", ["wrong-result", "private-error"])
def test_bad_protected_opener_returns_a_safe_error(tmp_path, failure):
    secret = "PUBLIC-TEST-opener-private-content"

    def opener(path):
        if failure == "private-error":
            raise RuntimeError(secret)
        return secret

    with pytest.raises(SecurityError) as caught:
        asyncio.run(FileLoader(file=tmp_path / "data.txt", opener=opener)())
    assert secret not in str(caught.value)
    assert caught.value.__context__ is None
    assert caught.value.__cause__ is None


def test_protected_transforms_receive_references_and_keep_process_line_hook(
    secret_store,
):
    source = secret_store.capture(b"one\ntwo\n")
    received = []

    class CustomLoader(FileLoader):
        def process_line(self, line, fn):
            received.append(line)
            return super().process_line(line, fn)

    values = asyncio.run(CustomLoader(file=source).process(lambda value: value))
    assert values == received
    assert all(isinstance(value, SecretString) for value in received)
