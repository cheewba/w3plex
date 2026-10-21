"""Characterize default ownership before adding caller-owned parse cleanup."""

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


@pytest.mark.parametrize("runner_api", [False, True])
@pytest.mark.parametrize("failure", ["success", "raise", "cancel"])
@pytest.mark.parametrize("kind", ["close", "generator", "async-generator"])
def test_external_owner_retains_resources_until_caller_closes(
    tmp_path, monkeypatch, runner_api, failure, kind
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
        runner, owner = Runner(), AsyncExitStack()
        try:

            async def parse():
                if runner_api:
                    await runner.init(
                        cfg, str(tmp_path / "config.yaml"), resource_owner=owner
                    )
                    return runner.tree
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
            # Finalizing the Runner also must not close the caller's resources.
            await runner.finalize()
            assert not runner.is_initialized
            assert calls == []
            await owner.aclose()
            await owner.aclose()
            assert calls == ["close"]
            with pytest.raises(OSError):
                os.fstat(descriptor)
        finally:
            await owner.aclose()
            await runner.finalize()
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
            await runner.finalize()

    asyncio.run(check())
