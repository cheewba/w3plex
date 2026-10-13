"""Optional encrypted YAML preserves the same factory and include semantics."""

import asyncio
import base64
import hashlib
from copy import deepcopy

from cryptography.fernet import Fernet

from w3plex.config import config_loader
from w3plex.config.reading import load_reference_config
from w3plex.security import SecretRef
from w3plex.security.legacy import LegacyContext


def test_captured_yaml_keeps_constructor_and_object_reference_strings(
    secret_store, tmp_path
):
    data = tmp_path / "data.txt"
    data.write_text("external data\n")
    source = secret_store.capture(
        b"reader:\n  __init__: w3plex.utils.loader:FileLoader\n  file: ${FILE}\n"
        b"alias: $reader\n"
    )
    cfg = load_reference_config(
        source, filename=tmp_path / "w3plex.yaml", environment={"FILE": "data.txt"}
    )
    assert cfg.reader["__init__"] == "w3plex.utils.loader:FileLoader"
    assert cfg.reader.file == "data.txt"
    assert cfg.alias == "$reader"

    async def check():
        tree = await config_loader.parse(
            cfg, str(tmp_path / "w3plex.yaml"), file_opener=secret_store.capture_file
        )
        try:
            assert tree.alias is tree.reader
            value = (await tree.reader())[0]
            assert isinstance(value, SecretRef)
            assert value.ref(silent=True) == "external data"
        finally:
            await tree.close()

    asyncio.run(check())


def test_captured_includes_keep_relative_paths_and_metadata(secret_store, tmp_path):
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "data.txt").write_text("included external data\n")
    (tmp_path / "data.txt").write_text("wrong directory\n")
    source = secret_store.capture(b"readers: !include nested/readers.yaml\n")
    included = secret_store.capture(
        b"lines:\n  __init__: w3plex.utils.loader:FileLoader\n  file: data.txt\n"
    )
    cfg = load_reference_config(
        source,
        filename=tmp_path / "w3plex.yaml",
        includes={nested / "readers.yaml": included},
        environment={},
    )
    assert cfg.readers.__include_path__ == str(nested / "readers.yaml")
    assert deepcopy(cfg).readers.__include_path__ == cfg.readers.__include_path__

    async def check():
        tree = await config_loader.parse(
            cfg, str(tmp_path / "w3plex.yaml"), file_opener=secret_store.capture_file
        )
        try:
            value = (await tree.readers.lines())[0]
            assert value.ref(silent=True) == "included external data"
        finally:
            await tree.close()

    asyncio.run(check())


def test_enc1_yaml_capture_survives_original_removal(secret_store, tmp_path):
    password = "PUBLIC-TEST-config-file-password"
    key = base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())
    raw = b"object:\n  __init__: types:SimpleNamespace\n  label: example\nalias: $object\n"
    encrypted = b"ENC1" + Fernet(key).encrypt(raw)
    path = tmp_path / "w3plex.yaml"
    path.write_bytes(encrypted)
    legacy = LegacyContext(None, input_handler=lambda request: password)
    source = secret_store.capture_file(path, legacy=legacy)
    assert path.read_bytes() == encrypted
    path.unlink()
    legacy.lock()
    cfg = load_reference_config(source, filename=path, environment={})

    async def check():
        tree = await config_loader.parse(cfg, str(path))
        try:
            assert tree.object.label == "example"
            assert tree.alias is tree.object
        finally:
            await tree.close()

    asyncio.run(check())
