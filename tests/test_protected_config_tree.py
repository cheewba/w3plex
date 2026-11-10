"""Existing configuration factories bind each reader to its trusted owner."""

import asyncio
import pickle
from copy import deepcopy

import pytest

from w3plex.config import config_loader
from w3plex.config.reading import load_config
from w3plex.core.objects import application
from w3plex.runner import Runner
from w3plex.security import ISecretRef, SecretStore
from w3plex.security.errors import PermissionDenied
from w3plex.security.storage import CiphertextFile
from w3plex.security.vault import Vault
from w3plex.utils.loader import FileLoader, get_file_opener, using_file_opener


@pytest.fixture
def other_store(vault_password, tmp_path, protection):
    directory = tmp_path / "other-secrets"
    directory.mkdir(mode=0o700)
    vault = Vault(CiphertextFile(directory / "vault"), protection=protection)
    try:
        vault.create(vault_password)
        vault.unlock(vault_password)
        yield SecretStore(vault)
    finally:
        vault.close()


def test_plain_yaml_keeps_factories_references_and_include_paths(
    vault, secret_store, tmp_path
):
    nested = tmp_path / "nested"
    nested.mkdir()
    (tmp_path / "data.txt").write_text("wrong directory\n")
    (nested / "data.txt").write_text("PUBLIC-TEST-private-line\n")
    (nested / "readers.yaml").write_text(
        "lines:\n  __init__: w3plex.utils.loader:FileLoader\n  file: data.txt\n"
    )
    path = tmp_path / "w3plex.yaml"
    path.write_text("readers: !include nested/readers.yaml\nalias: $readers.lines\n")
    cfg = load_config(path, opener=open, environment={})
    assert isinstance(cfg["readers"]["lines"]["__init__"], str)
    assert cfg["alias"] == "$readers.lines"

    async def check():
        runner = Runner()
        with using_file_opener(secret_store.capture_file):
            await runner.init(cfg, str(path))
        try:
            assert runner.tree.alias is runner.tree.readers.lines
            values = await runner.tree.alias()
            assert isinstance(values[0], ISecretRef)
            assert (
                vault.read(values[0].parent.identifier) == b"PUBLIC-TEST-private-line\n"
            )
            assert values[0].ref(silent=True) == "PUBLIC-TEST-private-line"
            assert get_file_opener() is None
        finally:
            await runner.finalize()

    asyncio.run(check())


def test_lazy_reader_retains_opener_after_initialization(vault, secret_store, tmp_path):
    data = tmp_path / "data.txt"
    data.write_text("deferred\n")
    cfg = {
        "reader": {
            "__init__": "w3plex.utils.loader:FileLoader",
            "__lazy__": True,
            "file": str(data),
        }
    }

    async def check():
        with using_file_opener(secret_store.capture_file):
            tree = await config_loader.parse(cfg, str(tmp_path / "w3plex.yaml"))
        try:
            assert get_file_opener() is None
            reader = await tree.reader()
            value = (await reader())[0]
            assert isinstance(value, ISecretRef)
            assert vault.read(value.parent.identifier) == b"deferred\n"
            assert value.ref(silent=True) == "deferred"
        finally:
            await tree.close()

    asyncio.run(check())


@pytest.mark.parametrize(
    ("as_factory", "asynchronous", "protected"),
    [
        pytest.param(False, False, False, id="lazy-sync-plain"),
        pytest.param(False, True, True, id="lazy-async-protected"),
        pytest.param(True, False, True, id="factory-sync-protected"),
        pytest.param(True, True, False, id="factory-async-plain"),
    ],
)
def test_generator_reader_factory_keeps_configured_opener(
    vault, secret_store, tmp_path, monkeypatch, as_factory, asynchronous, protected
):
    data = tmp_path / "data.txt"
    data.write_text("deferred generator\n")
    closed = []

    def factory(file):
        try:
            yield FileLoader(file=file)
        finally:
            closed.append(True)

    async def async_factory(file):
        await asyncio.sleep(0)
        try:
            yield FileLoader(file=file)
        finally:
            closed.append(True)

    monkeypatch.setattr(
        "w3plex.config.config.load_path",
        lambda path: async_factory if asynchronous else factory,
    )
    cfg = {
        "reader": {
            "__init__": "fixture:factory",
            "__factory__" if as_factory else "__lazy__": True,
            "file": str(data),
        }
    }

    async def check():
        with using_file_opener(secret_store.capture_file if protected else None):
            tree = await config_loader.parse(cfg, str(tmp_path / "w3plex.yaml"))
        try:
            reader = await tree.reader()
            assert get_file_opener() is None
            values = await reader()
            if protected:
                assert isinstance(values[0], ISecretRef)
                assert (
                    vault.read(values[0].parent.identifier) == b"deferred generator\n"
                )
                assert values[0].ref(silent=True) == "deferred generator"
            else:
                assert values == ["deferred generator"]
            again = await tree.reader()
            assert (again is reader) == (not as_factory)
        finally:
            await tree.close()
        assert closed == [True] * (2 if as_factory else 1)
        assert get_file_opener() is None

    asyncio.run(check())


def test_concurrent_factories_and_later_reads_keep_owner(
    vault, secret_store, other_store, tmp_path, monkeypatch
):
    async def factory(file):
        await asyncio.sleep(0)
        return FileLoader(file=file)

    monkeypatch.setattr("w3plex.config.config.load_path", lambda path: factory)
    paths = [tmp_path / "first.txt", tmp_path / "second.txt"]
    for path, value in zip(paths, ("first", "second"), strict=True):
        path.write_text(value + "\n")

    async def check():
        runners = [Runner(), Runner()]

        async def initialize(runner, path, store):
            with using_file_opener(store.capture_file):
                await runner.init(
                    {"reader": {"__init__": "fixture:factory", "file": str(path)}},
                    str(tmp_path / "w3plex.yaml"),
                )

        try:
            await asyncio.gather(
                *(
                    initialize(runner, path, store)
                    for runner, path, store in zip(
                        runners, paths, (secret_store, other_store), strict=True
                    )
                )
            )
            first, second = await asyncio.gather(
                *(runner.tree.reader() for runner in runners)
            )
            assert first[0].ref(silent=True) == "first"
            assert second[0].ref(silent=True) == "second"
            vault.lock()
            with pytest.raises(PermissionDenied):
                first[0].ref(silent=True)
            assert second[0].ref(silent=True) == "second"
            assert get_file_opener() is None
        finally:
            await asyncio.gather(*(runner.finalize() for runner in runners))

    asyncio.run(check())


def test_local_reference_configuration_deepcopy_keeps_identity(secret_store, tmp_path):
    source = secret_store.capture(b"local reference\n")
    assert deepcopy(source) is source
    with pytest.raises(PermissionDenied):
        pickle.dumps(source)
    cfg = {
        "source": source,
        "reader": {"__init__": "w3plex.utils.loader:FileLoader", "file": "$source"},
    }

    async def check():
        runner = Runner()
        await runner.init(cfg, str(tmp_path / "w3plex.yaml"))
        try:
            assert runner.cfg["source"] is source
            assert runner.tree.source is source
            value = (await runner.tree.reader())[0]
            assert value.parent is source
            assert value.ref(silent=True) == "local reference"
        finally:
            await runner.finalize()

    asyncio.run(check())


def test_failed_protected_factory_restores_context_and_runner_state(
    tmp_path, monkeypatch
):
    data = tmp_path / "data.txt"
    data.write_text("ordinary read\n")

    async def factory(file):
        return await FileLoader(file=file)()

    def denied(path):
        raise PermissionDenied()

    monkeypatch.setattr("w3plex.config.config.load_path", lambda path: factory)

    async def check():
        runner = Runner()
        with pytest.raises(PermissionDenied), using_file_opener(denied):
            await runner.init(
                {"reader": {"__init__": "fixture:factory", "file": str(data)}},
                str(tmp_path / "w3plex.yaml"),
            )
        assert not runner.is_initialized
        assert get_file_opener() is None
        assert await FileLoader(file=data)() == ["ordinary read"]

    asyncio.run(check())


def test_application_created_reader_uses_runner_opener(
    vault, secret_store, tmp_path, monkeypatch
):
    data = tmp_path / "data.txt"
    data.write_text("application read\n")
    received = []

    @application
    async def sample(action):
        yield 1

    @sample.action("read", default=True)
    async def read(item):
        received.extend(await FileLoader(file=data)())
        return "ok"

    monkeypatch.setattr("w3plex.runner.load_path", lambda path: sample)

    async def check():
        runner = Runner()
        with using_file_opener(secret_store.capture_file):
            await runner.init(
                {"applications": {"sample": {"__init__": "fixture:sample"}}},
                str(tmp_path / "w3plex.yaml"),
            )
        try:
            await runner.tree.applications.sample("read")
            assert isinstance(received[0], ISecretRef)
            assert vault.read(received[0].parent.identifier) == b"application read\n"
            assert received[0].ref(silent=True) == "application read"
            assert get_file_opener() is None
        finally:
            await runner.finalize()

    asyncio.run(check())
