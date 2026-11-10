"""Resource lifetime with tree-owned and caller-owned cleanup."""

import asyncio
import os
from contextlib import AsyncExitStack

import pytest

from w3plex.config import config_loader
from w3plex.runner import Runner


@pytest.mark.parametrize("runner_api", [False, True])
@pytest.mark.parametrize("failure", ["success", "raise", "cancel"])
def test_default_resources_close_once_after_success_or_failure(
    tmp_path, monkeypatch, runner_api, failure
):
    async def check():
        descriptor = os.open(tmp_path / "resource", os.O_CREAT | os.O_RDWR, 0o600)
        calls = []

        class Resource:
            async def close(self):
                calls.append("close")
                await asyncio.sleep(0)
                os.close(descriptor)

        async def later():
            if failure == "cancel":
                raise asyncio.CancelledError()
            raise ValueError("PUBLIC-TEST-constructor-failure")

        monkeypatch.setattr(
            "w3plex.config.config.load_path",
            lambda path: Resource if path == "fixture:resource" else later,
        )
        cfg = {"resource": {"__init__": "fixture:resource"}, "alias": "$resource"}
        if failure != "success":
            cfg["later"] = {"__init__": "fixture:later"}
        runner = Runner()
        try:
            if failure == "success":
                if runner_api:
                    await runner.init(cfg, str(tmp_path / "config.yaml"))
                    tree = runner.tree
                else:
                    tree = await config_loader.parse(cfg, str(tmp_path / "config.yaml"))
                assert tree.resource is tree.alias
                assert calls == []
                os.fstat(descriptor)
                if runner_api:
                    await runner.finalize()
                    await runner.finalize()
                else:
                    await tree.close()
                    await tree.close()
            else:
                with pytest.raises(
                    asyncio.CancelledError if failure == "cancel" else ValueError
                ):
                    if runner_api:
                        await runner.init(cfg, str(tmp_path / "config.yaml"))
                    else:
                        await config_loader.parse(cfg, str(tmp_path / "config.yaml"))
                if runner_api:
                    assert not runner.is_initialized
                    await runner.finalize()
            assert calls == ["close"]
            with pytest.raises(OSError):
                os.fstat(descriptor)
        finally:
            try:
                os.fstat(descriptor)
            except OSError:
                pass
            else:
                os.close(descriptor)

    asyncio.run(check())


def test_runner_preserves_configured_load_attribute(tmp_path):
    async def check():
        runner = Runner()
        await runner.init({"load": "configured-value"}, str(tmp_path / "config.yaml"))
        try:
            assert runner.tree.load == "configured-value"
        finally:
            await runner.finalize()

    asyncio.run(check())


def test_cancelled_runner_build_finishes_its_cleanup_before_retry(
    tmp_path, monkeypatch
):
    async def check():
        constructed, closing, resume = asyncio.Event(), asyncio.Event(), asyncio.Event()
        descriptor = os.open(tmp_path / "resource", os.O_CREAT | os.O_RDWR, 0o600)
        calls = []

        class Resource:
            async def close(self):
                calls.append("started")
                closing.set()
                await resume.wait()
                os.close(descriptor)
                calls.append("closed")

        async def blocking():
            constructed.set()
            await asyncio.Event().wait()

        monkeypatch.setattr(
            "w3plex.config.config.load_path",
            lambda path: Resource if path == "fixture:resource" else blocking,
        )
        runner = Runner()
        loading = asyncio.create_task(
            runner.init(
                {
                    "resource": {"__init__": "fixture:resource"},
                    "blocking": {"__init__": "fixture:blocking"},
                },
                str(tmp_path / "config.yaml"),
            )
        )
        retry = None
        try:
            await asyncio.wait_for(constructed.wait(), 2)
            loading.cancel()
            await asyncio.wait_for(closing.wait(), 2)
            loading.cancel()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(loading, 2)
            assert not runner.is_initialized
            with pytest.raises(RuntimeError):
                _ = runner.tree
            os.fstat(descriptor)
            retry = asyncio.create_task(
                runner.init({"label": "new-root"}, str(tmp_path / "config.yaml"))
            )
            await asyncio.sleep(0)
            assert not retry.done()
            resume.set()
            await asyncio.wait_for(retry, 2)
            assert runner.tree.label == "new-root"
            assert calls == ["started", "closed"]
            with pytest.raises(OSError):
                os.fstat(descriptor)
        finally:
            resume.set()
            await asyncio.gather(
                loading, *([retry] if retry is not None else []), return_exceptions=True
            )
            await runner.finalize()
            try:
                os.fstat(descriptor)
            except OSError:
                pass
            else:
                os.close(descriptor)

    asyncio.run(check())


@pytest.mark.parametrize("runner_api", [False, True])
def test_concurrent_close_waiters_keep_one_cleanup_after_cancellation(
    tmp_path, monkeypatch, runner_api
):
    async def check():
        started, resume = asyncio.Event(), asyncio.Event()
        calls = []

        class Resource:
            async def close(self):
                calls.append("started")
                started.set()
                await resume.wait()
                calls.append("closed")

        monkeypatch.setattr("w3plex.config.config.load_path", lambda path: Resource)
        cfg = {"resource": {"__init__": "fixture:resource"}, "alias": "$resource"}
        runner = Runner()
        if runner_api:
            await runner.init(cfg, str(tmp_path / "config.yaml"))
            close = runner.finalize
        else:
            tree = await config_loader.parse(cfg, str(tmp_path / "config.yaml"))
            close = tree.close
        first = asyncio.create_task(close())
        await asyncio.wait_for(started.wait(), 2)
        second = asyncio.create_task(close())
        try:
            first.cancel()
            with pytest.raises(asyncio.CancelledError):
                await first
            assert not second.done()
            resume.set()
            await asyncio.wait_for(second, 2)
            await close()
            assert calls == ["started", "closed"]
        finally:
            resume.set()
            await asyncio.gather(first, second, return_exceptions=True)

    asyncio.run(check())


@pytest.mark.parametrize(
    ("failure", "kind"),
    [
        ("success", "close"),
        ("raise", "close"),
        ("cancel", "close"),
        # Generator cleanup shares the same owner once it is registered.
        ("success", "generator"),
        ("raise", "generator"),
        ("success", "async-generator"),
        ("cancel", "async-generator"),
    ],
)
def test_external_parser_owner_retains_resources_until_caller_closes(
    tmp_path, monkeypatch, failure, kind
):
    async def check():
        descriptor = os.open(tmp_path / "resource", os.O_CREAT | os.O_RDWR, 0o600)
        calls = []

        class Resource:
            async def close(self):
                calls.append("close")
                os.close(descriptor)

        def generator():
            try:
                yield "resource"
            finally:
                calls.append("close")
                os.close(descriptor)

        async def async_generator():
            try:
                yield "resource"
            finally:
                calls.append("close")
                os.close(descriptor)

        async def later():
            if failure == "cancel":
                raise asyncio.CancelledError()
            raise ValueError("PUBLIC-TEST-constructor-failure")

        selected = {
            "close": Resource,
            "generator": generator,
            "async-generator": async_generator,
        }[kind]
        monkeypatch.setattr(
            "w3plex.config.config.load_path",
            lambda path: selected if path == "fixture:resource" else later,
        )
        cfg = {"resource": {"__init__": "fixture:resource"}, "alias": "$resource"}
        if failure != "success":
            cfg["later"] = {"__init__": "fixture:later"}
        owner = AsyncExitStack()
        try:

            async def parse():
                return await config_loader.parse(
                    cfg, str(tmp_path / "config.yaml"), resource_owner=owner
                )

            if failure == "success":
                tree = await parse()
                assert tree.resource is tree.alias
                await tree.close()
                await tree.close()
            else:
                with pytest.raises(
                    asyncio.CancelledError if failure == "cancel" else ValueError
                ):
                    await parse()
            os.fstat(descriptor)
            assert calls == []
            await owner.aclose()
            await owner.aclose()
            assert calls == ["close"]
            with pytest.raises(OSError):
                os.fstat(descriptor)
        finally:
            await owner.aclose()
            try:
                os.fstat(descriptor)
            except OSError:
                pass
            else:
                os.close(descriptor)

    asyncio.run(check())


@pytest.mark.parametrize("runner_api", [False, True])
def test_default_failed_parse_preserves_closer_error(tmp_path, monkeypatch, runner_api):
    class CloseFailure(Exception):
        pass

    class Resource:
        def close(self):
            raise CloseFailure("PUBLIC-TEST-close-failure")

    monkeypatch.setattr("w3plex.config.config.load_path", lambda path: Resource)

    async def check():
        cfg = {"resource": {"__init__": "fixture:resource"}, "missing": "$absent"}
        runner = Runner()
        with pytest.raises(CloseFailure):
            if runner_api:
                await runner.init(cfg, str(tmp_path / "config.yaml"))
            else:
                await config_loader.parse(cfg, str(tmp_path / "config.yaml"))
        if runner_api:
            assert not runner.is_initialized
            with pytest.raises(CloseFailure):
                await runner.finalize()
            with pytest.raises(CloseFailure):
                await runner.init({}, str(tmp_path / "config.yaml"))

    asyncio.run(check())
