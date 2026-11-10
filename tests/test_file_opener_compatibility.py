"""Characterization verified before adding optional async file capture."""

import asyncio
import threading
from dataclasses import dataclass

import pytest

from w3plex.config import config_loader
from w3plex.runner import Runner
from w3plex.security.errors import PermissionDenied
from w3plex.utils.loader import (
    FileLoader,
    accounts_loader,
    get_file_opener,
    using_file_opener,
)


@dataclass
class Reference:
    value: bytes

    def ref(self, *, silent=False):
        return self.value


def reveal(values):
    return [value.ref(silent=True) for value in values]


@pytest.mark.parametrize("factory", [FileLoader, accounts_loader])
@pytest.mark.parametrize("option", ["opener", "async_opener"])
def test_reader_rejects_explicit_openers(factory, option):
    with pytest.raises(TypeError, match=option):
        factory(file="unused", **{option: lambda path: Reference(b"unused")})


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


@pytest.mark.parametrize("runner", [False, True])
@pytest.mark.parametrize("failure", [ValueError, asyncio.CancelledError])
def test_failed_construction_preserves_caller_context(
    tmp_path, monkeypatch, runner, failure
):
    def outer(path):
        return Reference(b"outer\n")

    def inner(path):
        return Reference(b"inner\n")

    async def factory():
        assert get_file_opener() is (inner if runner else outer)
        raise failure()

    monkeypatch.setattr("w3plex.config.config.load_path", lambda path: factory)

    async def check():
        cfg = {"value": {"__init__": "fixture:factory"}}
        with using_file_opener(outer):
            with pytest.raises(failure):
                if runner:
                    await Runner().init(
                        cfg, str(tmp_path / "config.yaml"), file_opener=inner
                    )
                else:
                    await config_loader.parse(cfg, str(tmp_path / "config.yaml"))
            assert get_file_opener() is outer
        assert get_file_opener() is None

    asyncio.run(check())


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


@pytest.mark.parametrize("runner", [False, True])
def test_cancelled_construction_restores_sync_context(tmp_path, monkeypatch, runner):
    entered = asyncio.Event()

    async def factory():
        assert get_file_opener() is opener
        entered.set()
        await asyncio.Future()

    def opener(path):
        return Reference(b"unused")

    monkeypatch.setattr("w3plex.config.config.load_path", lambda path: factory)

    async def check():
        cfg = {"value": {"__init__": "fixture:factory"}}
        host = Runner() if runner else config_loader

        async def construct():
            if runner:
                await host.init(cfg, str(tmp_path / "config.yaml"), file_opener=opener)
            else:
                with using_file_opener(opener):
                    await host.parse(cfg, str(tmp_path / "config.yaml"))

        task = asyncio.create_task(construct())
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert get_file_opener() is None
        if runner:
            assert not host.is_initialized
            assert host._file_opener is None

    asyncio.run(check())
