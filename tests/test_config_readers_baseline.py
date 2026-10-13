"""Existing YAML factories and external-file reads before protected-mode edits."""

import asyncio
import base64
import hashlib

from cryptography.fernet import Fernet
from w3ext import Account

from w3plex.config import Lazy, config_loader
from w3plex.config.reading import load_config
from w3plex.runner import Runner
from w3plex.security.legacy import LegacyContext
from w3plex.utils.loader import FileLoader

KEY = "11" * 32


def test_yaml_builds_existing_readers_and_object_references(tmp_path):
    (tmp_path / "keys.txt").write_text(KEY + "\n")
    config = tmp_path / "w3plex.yaml"
    config.write_text(
        "accounts:\n"
        "  main:\n"
        "    __init__: w3plex.utils.loader:accounts_loader\n"
        "    file: keys.txt\n"
        "alias: $accounts.main\n"
    )
    cfg = load_config(config, opener=open, environment={})

    async def check():
        runner = Runner()
        await runner.init(cfg, str(config))
        try:
            assert runner.tree.alias is runner.tree.accounts.main
            accounts = await runner.tree.accounts.main()
            assert type(accounts[0]) is Account
            assert accounts[0].key == bytes.fromhex(KEY)
            assert runner.cfg["accounts"]["main"]["file"] == "keys.txt"
        finally:
            await runner.finalize()

    asyncio.run(check())


def test_nested_include_resolves_reader_path_from_included_yaml(tmp_path):
    nested = tmp_path / "nested"
    nested.mkdir()
    (tmp_path / "data.txt").write_text("wrong directory\n")
    (nested / "data.txt").write_text("included directory\n")
    (nested / "readers.yaml").write_text(
        "lines:\n  __init__: w3plex.utils.loader:FileLoader\n  file: data.txt\n"
    )
    config = tmp_path / "w3plex.yaml"
    config.write_text("readers: !include nested/readers.yaml\n")
    cfg = load_config(config, opener=open, environment={})

    async def check():
        tree = await config_loader.parse(cfg, str(config))
        try:
            assert isinstance(tree.readers.lines, FileLoader)
            assert await tree.readers.lines() == ["included directory"]
        finally:
            await tree.close()

    asyncio.run(check())


def test_existing_reader_reopens_plain_file_on_each_call(tmp_path):
    data = tmp_path / "data.txt"
    data.write_text("first\n")
    cfg = {"reader": {"__init__": "w3plex.utils.loader:FileLoader", "file": str(data)}}

    async def check():
        tree = await config_loader.parse(cfg, str(tmp_path / "w3plex.yaml"))
        try:
            assert await tree.reader() == ["first"]
            data.write_text("second\n")
            assert await tree.reader() == ["second"]
        finally:
            await tree.close()

    asyncio.run(check())


def test_lazy_file_reader_works_after_tree_construction(tmp_path):
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
        tree = await config_loader.parse(cfg, str(tmp_path / "w3plex.yaml"))
        try:
            assert isinstance(tree.reader, Lazy)
            reader = await tree.reader()
            assert isinstance(reader, FileLoader)
            assert await reader() == ["deferred"]
        finally:
            await tree.close()

    asyncio.run(check())


def test_accounts_factory_reads_enc1_through_existing_open(tmp_path):
    password = "PUBLIC-TEST-reader-password"
    key = base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())
    encrypted = b"ENC1" + Fernet(key).encrypt((KEY + "\n").encode())
    data = tmp_path / "keys.enc"
    data.write_bytes(encrypted)
    cfg = {
        "accounts": {
            "__init__": "w3plex.utils.loader:accounts_loader",
            "file": str(data),
        }
    }
    legacy = LegacyContext(None, input_handler=lambda request: password)

    async def check():
        tree = await config_loader.parse(cfg, str(tmp_path / "w3plex.yaml"))
        try:
            with legacy.activated():
                accounts = await tree.accounts()
            assert type(accounts[0]) is Account
            assert accounts[0].key == bytes.fromhex(KEY)
            assert data.read_bytes() == encrypted
        finally:
            await tree.close()
            legacy.lock()

    asyncio.run(check())
