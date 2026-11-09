"""Opt-in capture awaits the opener in the invoking task, once per reader."""

import asyncio
import threading
from dataclasses import dataclass
from functools import partial

import pytest

from w3plex.config import config_loader
from w3plex.core.objects import application
from w3plex.runner import Runner
from w3plex.security import SecretString
from w3plex.security.errors import InteractionRequired, PermissionDenied, SecurityError
from w3plex.utils.loader import (
    FileLoader,
    accounts_loader,
    get_file_opener,
    using_file_opener,
)

PASSWORD = b"PUBLIC-TEST-snapshot-password"


@dataclass
class Reference:
    value: bytes

    def ref(self, *, silent=False):
        return self.value


def reveal(values):
    return [value.ref(silent=True) for value in values]


def adapt_opener(opener, kind):
    if kind == "partial":
        return partial(opener)
    if kind == "callable":

        class Opener:
            async def __call__(self, path):
                return await opener(path)

        return Opener()
    if kind == "factory":
        return lambda path: opener(path)
    if kind == "awaitable":

        class Capture:
            def __init__(self, path):
                self.path = path

            def __await__(self):
                return opener(self.path).__await__()

        return Capture
    return opener


@pytest.mark.parametrize(
    "kind", ["function", "partial", "callable", "factory", "awaitable"]
)
def test_capture_stays_on_invoking_task_and_serializes_competing_reads(kind):
    async def check():
        entered = asyncio.Event()
        release = asyncio.Event()
        calls = []
        source = Reference(b"one\ntwo\n")

        async def opener(path):
            calls.append(asyncio.current_task())
            entered.set()
            await release.wait()
            return source

        with using_file_opener(adapt_opener(opener, kind)):
            reader = FileLoader(file="unused")
        first = asyncio.create_task(reader())
        await entered.wait()
        second = asyncio.create_task(reader())
        await asyncio.sleep(0)
        assert calls == [first]
        release.set()
        values = await asyncio.gather(first, second)
        assert [reveal(value) for value in values] == [["one", "two"]] * 2
        assert all(line.parent is source for value in values for line in value)
        assert calls == [first]

    asyncio.run(check())


@pytest.mark.parametrize("failure", ["private-error", "wrong-result", "interaction"])
def test_failed_capture_is_safe_and_retries(failure):
    async def check():
        owner = asyncio.current_task()
        calls = []

        async def opener(path):
            assert asyncio.current_task() is owner
            calls.append(path)
            if len(calls) == 1:
                if failure == "private-error":
                    raise RuntimeError("PUBLIC-TEST-private-error")
                if failure == "interaction":
                    raise InteractionRequired()
                return b"PUBLIC-TEST-private-error"
            return Reference(b"recovered\n")

        with using_file_opener(opener):
            reader = FileLoader(file="unused")
        expected = InteractionRequired if failure == "interaction" else SecurityError
        with pytest.raises(expected) as caught:
            await reader()
        assert "PUBLIC-TEST-private-error" not in str(caught.value)
        assert caught.value.__context__ is None
        assert caught.value.__cause__ is None
        assert reveal(await reader()) == ["recovered"]
        assert calls == ["unused", "unused"]

    asyncio.run(check())


@pytest.mark.parametrize(
    "kind", ["function", "partial", "callable", "factory", "awaitable"]
)
def test_capture_cancellation_releases_lock_for_waiting_reader(kind):
    async def check():
        entered = asyncio.Event()
        calls = []

        async def opener(path):
            calls.append(asyncio.current_task())
            if len(calls) == 1:
                entered.set()
                await asyncio.Future()
            return Reference(b"retry\n")

        with using_file_opener(adapt_opener(opener, kind)):
            reader = FileLoader(file="unused")
        first = asyncio.create_task(reader())
        await entered.wait()
        second = asyncio.create_task(reader())
        await asyncio.sleep(0)
        first.cancel("PUBLIC-TEST-private-cancellation")
        with pytest.raises(asyncio.CancelledError) as caught:
            await first
        assert not caught.value.args
        assert caught.value.__context__ is None
        assert reveal(await second) == ["retry"]
        assert reveal(await reader()) == ["retry"]
        assert calls == [first, second]

    asyncio.run(check())


def test_cancelled_waiter_does_not_discard_successful_capture():
    async def check():
        entered = asyncio.Event()
        release = asyncio.Event()
        calls = []

        async def opener(path):
            calls.append(path)
            entered.set()
            await release.wait()
            return Reference(b"retained\n")

        with using_file_opener(opener):
            reader = FileLoader(file="unused")
        first = asyncio.create_task(reader())
        await entered.wait()
        waiter = asyncio.create_task(reader())
        await asyncio.sleep(0)
        waiter.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiter
        release.set()
        assert reveal(await first) == ["retained"]
        assert reveal(await reader()) == ["retained"]
        assert calls == ["unused"]

    asyncio.run(check())


def test_cancelled_sync_factory_closes_unawaited_coroutine_and_retries():
    entered = threading.Event()
    release = threading.Event()
    created = []
    calls = []

    async def capture():
        calls.append(asyncio.current_task())
        return Reference(b"retry\n")

    def opener(path):
        entered.set()
        assert release.wait(5)
        result = capture()
        created.append(result)
        return result

    async def check():
        with using_file_opener(opener):
            reader = FileLoader(file="unused")
        task = asyncio.create_task(reader())
        try:
            assert await asyncio.to_thread(entered.wait, 5)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        finally:
            release.set()

        async def wait_for_cleanup():
            while not created or created[0].cr_frame is not None:
                await asyncio.sleep(0)

        await asyncio.wait_for(wait_for_cleanup(), 5)
        assert calls == []
        assert reveal(await reader()) == ["retry"]
        assert calls == [asyncio.current_task()]

    asyncio.run(check())


@pytest.mark.parametrize("asynchronous", [False, True])
def test_existing_reference_precedes_opener(asynchronous):
    def sync_opener(path):
        pytest.fail("Existing reference must not be reopened")

    async def async_opener(path):
        pytest.fail("Existing reference must not be reopened")

    source = Reference(b"reference\n")
    with using_file_opener(async_opener if asynchronous else sync_opener):
        reader = FileLoader(file=source)
    values = asyncio.run(reader())
    assert values[0].parent is source
    assert reveal(values) == ["reference"]


def test_nested_async_contexts_and_sync_fallback(tmp_path):
    path = tmp_path / "data.txt"
    path.write_text("plain\n")

    async def inherited(path):
        return Reference(b"inherited\n")

    async def nested(path):
        return Reference(b"nested\n")

    def sync_opener(path):
        return Reference(b"sync\n")

    with using_file_opener(inherited):
        default = FileLoader(file=path)
        with using_file_opener(sync_opener):
            sync = FileLoader(file=path)
        with using_file_opener(nested):
            override = FileLoader(file=path)
        with using_file_opener(None):
            plain = FileLoader(file=path)
        assert get_file_opener() is inherited
    assert get_file_opener() is None
    assert reveal(asyncio.run(default())) == ["inherited"]
    assert reveal(asyncio.run(override())) == ["nested"]
    assert reveal(asyncio.run(sync())) == ["sync"]
    assert asyncio.run(plain()) == ["plain"]


def test_async_snapshot_keeps_offsets_transforms_and_survives_lock(
    secret_store, tmp_path
):
    path = tmp_path / "data.txt"
    raw = "\ufeff # comment\r\n éclair \r two\n".encode()
    path.write_bytes(raw)
    calls = []

    async def opener(file):
        calls.append(file)
        await asyncio.sleep(0)
        return secret_store.capture_file(file)

    async def check():
        with using_file_opener(opener):
            reader = FileLoader(file=path, filter=r" (?:éclair|two)")
        seen = []
        values = await reader.process(lambda line: seen.append(line) or line)
        assert values == seen
        assert all(isinstance(line, SecretString) for line in values)
        assert reveal(values) == ["éclair", "two"]
        secret_store._vault.lock()
        path.unlink()
        with pytest.raises(PermissionDenied):
            await reader()
        secret_store._vault.unlock(PASSWORD)
        assert reveal(await reader()) == ["éclair", "two"]
        assert reveal(values) == ["éclair", "two"]
        assert calls == [path]

    asyncio.run(check())


def test_async_accounts_callable_defers_capture_to_current_task():
    async def check():
        calls = []
        owner = asyncio.current_task()

        async def opener(path):
            calls.append(asyncio.current_task())
            return Reference(("11" * 32 + "\n").encode())

        with using_file_opener(opener):
            reader = accounts_loader(file="unused")
        assert calls == []
        first = (await reader())[0]
        second = (await reader())[0]
        assert first.address == second.address
        assert calls == [owner]

    asyncio.run(check())


@pytest.mark.parametrize(
    "kind", ["direct", "lazy", "factory", "generator", "async-generator"]
)
@pytest.mark.parametrize("use_runner", [False, True])
def test_late_config_readers_retain_async_context(
    tmp_path, monkeypatch, kind, use_runner
):
    calls = []
    closed = []

    async def opener(path):
        calls.append((path, asyncio.current_task()))
        return Reference(b"configured\n")

    def factory(file):
        return FileLoader(file=file)

    def generator(file):
        try:
            yield FileLoader(file=file)
        finally:
            closed.append(True)

    async def async_generator(file):
        await asyncio.sleep(0)
        try:
            yield FileLoader(file=file)
        finally:
            closed.append(True)

    initializer = {"generator": generator, "async-generator": async_generator}.get(
        kind, factory
    )
    monkeypatch.setattr("w3plex.config.config.load_path", lambda path: initializer)
    cfg = {"reader": {"__init__": "fixture:factory", "file": "unused"}}
    if kind != "direct":
        cfg["reader"]["__factory__" if kind == "factory" else "__lazy__"] = True

    async def check():
        host = Runner() if use_runner else None
        if host is not None:
            await host.init(cfg, str(tmp_path / "config.yaml"), file_opener=opener)
            tree = host.tree
        else:
            tree = await config_loader.parse(
                cfg, str(tmp_path / "config.yaml"), file_opener=opener
            )
        try:
            assert get_file_opener() is None
            reader = tree.reader if kind == "direct" else await tree.reader()
            assert get_file_opener() is None
            assert reveal(await reader()) == ["configured"]
            assert calls == [("unused", asyncio.current_task())]
        finally:
            await (host.finalize() if host is not None else tree.close())
        assert get_file_opener() is None
        if host is not None:
            assert host._file_opener is None
        assert closed == ([True] if "generator" in kind else [])

    asyncio.run(check())


@pytest.mark.parametrize("failure", ["error", "cancel"])
def test_failed_runner_restores_async_context_and_can_reinitialize(
    tmp_path, monkeypatch, failure
):
    async def opener(path):
        if failure == "cancel":
            raise asyncio.CancelledError()
        raise InteractionRequired()

    async def factory():
        return await FileLoader(file="unused")()

    monkeypatch.setattr("w3plex.config.config.load_path", lambda path: factory)

    async def check():
        runner = Runner()
        expected = (
            asyncio.CancelledError if failure == "cancel" else InteractionRequired
        )
        with pytest.raises(expected):
            await runner.init(
                {"value": {"__init__": "fixture:factory"}},
                str(tmp_path / "config.yaml"),
                file_opener=opener,
            )
        assert not runner.is_initialized
        assert runner._file_opener is None
        assert get_file_opener() is None
        await runner.init({}, str(tmp_path / "config.yaml"))
        await runner.finalize()

    asyncio.run(check())


def test_application_created_readers_use_runner_async_context(tmp_path, monkeypatch):
    calls = []
    owners = []

    async def opener(path):
        calls.append(asyncio.current_task())
        return Reference(b"application\n")

    @application
    async def sample(action):
        yield 1

    @sample.action("read", default=True)
    async def read(item):
        owners.append(asyncio.current_task())
        assert reveal(await FileLoader(file="unused")()) == ["application"]

    monkeypatch.setattr("w3plex.runner.load_path", lambda path: sample)

    async def check():
        runner = Runner()
        await runner.init(
            {"applications": {"sample": {"__init__": "fixture:sample"}}},
            str(tmp_path / "config.yaml"),
            file_opener=opener,
        )
        try:
            await runner.tree.applications.sample("read")
            assert calls == owners
            assert len(calls) == 1
            assert get_file_opener() is None
        finally:
            await runner.finalize()

    asyncio.run(check())


@pytest.mark.parametrize("mixed", [False, True])
def test_concurrent_parsers_keep_independent_late_openers(tmp_path, monkeypatch, mixed):
    async def factory(file):
        await asyncio.sleep(0)
        return FileLoader(file=file)

    monkeypatch.setattr("w3plex.config.config.load_path", lambda path: factory)

    async def check():
        async def first_opener(path):
            await asyncio.sleep(0)
            return Reference(b"first\n")

        async def second_opener(path):
            await asyncio.sleep(0)
            return Reference(b"second\n")

        def second_sync_opener(path):
            return Reference(b"second\n")

        def cfg():
            return {
                "reader": {
                    "__init__": "fixture:factory",
                    "__lazy__": True,
                    "file": "unused",
                }
            }

        trees = await asyncio.gather(
            *(
                config_loader.parse(
                    cfg(), str(tmp_path / "config.yaml"), file_opener=opener
                )
                for opener in (
                    first_opener,
                    second_sync_opener if mixed else second_opener,
                )
            )
        )
        try:
            readers = await asyncio.gather(*(tree.reader() for tree in trees))
            values = await asyncio.gather(*(reader() for reader in readers))
            assert [reveal(lines) for lines in values] == [["first"], ["second"]]
            assert get_file_opener() is None
        finally:
            await asyncio.gather(*(tree.close() for tree in trees))

    asyncio.run(check())
