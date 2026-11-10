"""File opener context in config parsing, lazy factories and applications."""

import asyncio
from dataclasses import dataclass

import pytest

from w3plex.config import config_loader
from w3plex.core.objects import application
from w3plex.runner import Runner
from w3plex.security.errors import InteractionRequired
from w3plex.utils.loader import FileLoader, get_file_opener, using_file_opener


@dataclass
class Reference:
    value: bytes

    def ref(self, *, silent=False):
        return self.value


def reveal(values):
    return [value.ref(silent=True) for value in values]


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
        assert get_file_opener() is inner
        raise failure()

    monkeypatch.setattr("w3plex.config.config.load_path", lambda path: factory)

    async def check():
        cfg = {"value": {"__init__": "fixture:factory"}}
        with using_file_opener(outer):
            with pytest.raises(failure), using_file_opener(inner):
                if runner:
                    await Runner().init(cfg, str(tmp_path / "config.yaml"))
                else:
                    await config_loader.parse(cfg, str(tmp_path / "config.yaml"))
            assert get_file_opener() is outer
        assert get_file_opener() is None

    asyncio.run(check())


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
                with using_file_opener(opener):
                    await host.init(cfg, str(tmp_path / "config.yaml"))
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

    asyncio.run(check())


@pytest.mark.parametrize(
    ("kind", "use_runner"),
    [
        ("direct", False),
        ("direct", True),
        ("lazy", True),
        ("factory", False),
        ("generator", False),
        ("async-generator", False),
    ],
)
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
            with using_file_opener(opener):
                await host.init(cfg, str(tmp_path / "config.yaml"))
            tree = host.tree
        else:
            with using_file_opener(opener):
                tree = await config_loader.parse(cfg, str(tmp_path / "config.yaml"))
                assert get_file_opener() is opener
        try:
            assert get_file_opener() is None
            reader = tree.reader if kind == "direct" else await tree.reader()
            assert get_file_opener() is None
            assert reveal(await reader()) == ["configured"]
            assert calls == [("unused", asyncio.current_task())]
        finally:
            await (host.finalize() if host is not None else tree.close())
        assert get_file_opener() is None
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
        with pytest.raises(expected), using_file_opener(opener):
            await runner.init(
                {"value": {"__init__": "fixture:factory"}},
                str(tmp_path / "config.yaml"),
            )
        assert not runner.is_initialized
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
        with using_file_opener(opener):
            await runner.init(
                {"applications": {"sample": {"__init__": "fixture:sample"}}},
                str(tmp_path / "config.yaml"),
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

        async def parse_with_opener(opener):
            with using_file_opener(opener):
                return await config_loader.parse(cfg(), str(tmp_path / "config.yaml"))

        trees = await asyncio.gather(
            *(
                parse_with_opener(opener)
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
