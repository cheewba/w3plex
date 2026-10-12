"""Additive API checks; fixed ciphertexts originate from the old implementation."""

import builtins
import hashlib
import importlib
import json
import os
import sys
from pathlib import Path

import pytest

from w3plex.security.errors import InteractionRequired, InvalidStore
from w3plex.security.legacy import LegacyContext

FIXTURES = Path(__file__).parent / "fixtures" / "legacy-security"


def test_new_reader_does_not_touch_legacy_global_state(monkeypatch):
    previous = builtins.open
    try:
        old = importlib.import_module("w3plex.secure")
    finally:
        builtins.open = previous
    before = (old._KEYSTORE_PATH, old._salt, old._master_key)

    def forbidden(prompt):
        raise AssertionError("New context must not use global legacy input")

    monkeypatch.setattr(old.getpass, "getpass", forbidden)
    manifest = json.loads((FIXTURES / "manifest.json").read_text())
    context = LegacyContext(
        FIXTURES / "ks01-4096.bin",
        input_handler=lambda request: manifest["master_password"],
    )
    with context.open(FIXTURES / "sample.enc", "rb") as stream:
        assert stream.read() == bytes.fromhex(manifest["plaintext_hex"])
    assert (old._KEYSTORE_PATH, old._salt, old._master_key) == before
    assert builtins.open is previous
    context.lock()


@pytest.mark.parametrize("n", [4096, 8192, 16384, 32768])
def test_new_context_reads_fixed_historical_settings(tmp_path, n):
    manifest = json.loads((FIXTURES / "manifest.json").read_text())
    store = tmp_path / "store"
    store.write_bytes((FIXTURES / f"ks01-{n}.bin").read_bytes())
    prompts = []

    def answer(request):
        prompts.append(request.kind)
        return manifest["master_password"]

    context = LegacyContext(store, input_handler=answer)
    before = store.read_bytes()
    for _ in range(2):
        with context.open(FIXTURES / "sample.enc", "rb") as stream:
            assert stream.read() == bytes.fromhex(manifest["plaintext_hex"])
            assert stream.name == str(FIXTURES / "sample.enc")
    assert prompts == ["master"]
    assert store.read_bytes() == before
    context.lock()
    with context.open(FIXTURES / "sample.enc", encoding="utf-8", newline="") as stream:
        assert stream.read() == bytes.fromhex(manifest["plaintext_hex"]).decode()
    assert prompts == ["master", "master"]


def test_contexts_and_legacy_global_are_independent(tmp_path):
    manifest = json.loads((FIXTURES / "manifest.json").read_text())
    a = LegacyContext(
        FIXTURES / "ks01-4096.bin",
        input_handler=lambda request: manifest["master_password"],
    )
    b = LegacyContext(tmp_path / "missing")
    with a.open(FIXTURES / "sample.enc", "rb") as stream:
        assert stream.read()
    with pytest.raises(InteractionRequired):
        b.open(FIXTURES / "sample.enc", "rb")
    assert b._keys is None
    # The legacy API is tested in its own process and is never imported here.
    assert (
        "w3plex.secure" not in sys.modules
        or a._keys is not sys.modules["w3plex.secure"]._master_key
    )


def test_no_stdin_fallback_and_damaged_store_is_not_empty_success(tmp_path):
    context = LegacyContext(tmp_path / "store")
    with pytest.raises(InteractionRequired):
        context.open(FIXTURES / "sample.enc", "rb")
    context.path.write_bytes(b"s" * 16 + b"not-json")
    with pytest.raises(InvalidStore):
        context.open(FIXTURES / "sample.enc", "rb")
    assert context.path.read_bytes() == b"s" * 16 + b"not-json"


def test_file_password_cache_and_cancel_are_context_local(tmp_path):
    manifest = json.loads((FIXTURES / "manifest.json").read_text())
    calls = []

    def answer(request):
        calls.append(request.kind)
        return manifest["file_password"]

    context = LegacyContext(tmp_path / "missing", input_handler=answer)
    with context.open(FIXTURES / "sample.enc", encoding="utf-8", newline="") as stream:
        assert stream.read().encode() == bytes.fromhex(manifest["plaintext_hex"])
    with context.open(FIXTURES / "sample.enc", "rb") as stream:
        assert stream.read()
    assert calls == ["file"]
    assert not context.path.exists()
    context.lock()

    def cancel(request):
        raise KeyboardInterrupt()

    context._input = cancel
    with pytest.raises(KeyboardInterrupt):
        context.open(FIXTURES / "sample.enc", "rb")
    assert context._keys is None


def test_plain_descriptor_pipe_and_write_modes(tmp_path):
    context = LegacyContext(tmp_path / "missing")
    path = tmp_path / "plain"
    path.write_bytes(b"caf\xe9\r\nline\r")
    with context.open(path, encoding="latin-1", newline="") as stream:
        assert stream.read() == "caf\u00e9\r\nline\r"
    with context.open(path, encoding="ascii", errors="replace") as stream:
        assert "\ufffd" in stream.read()
    fd = os.open(path, os.O_RDONLY)
    with context.open(fd, "rb", closefd=False) as stream:
        assert stream.read() == path.read_bytes()
    os.close(fd)
    rfd, wfd = os.pipe()
    os.write(wfd, b"ENC1raw")
    os.close(wfd)
    with context.open(rfd, "rb") as stream:
        assert stream.read() == b"ENC1raw"
    with context.open(path, "ab") as stream:
        stream.write(b"tail")
    with context.open(path, "r+b") as stream:
        assert stream.read().endswith(b"tail")
    with context.open(path, "wb") as stream:
        stream.write(b"replace")
    assert path.read_bytes() == b"replace"


def test_fixture_hashes_stay_fixed():
    manifest = json.loads((FIXTURES / "manifest.json").read_text())
    for filename, digest in manifest["sha256"].items():
        assert hashlib.sha256((FIXTURES / filename).read_bytes()).hexdigest() == digest


def test_bytes_filename_and_explicit_absence_of_keystore(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".unused-keystore").write_bytes(b"must not be read")
    manifest = json.loads((FIXTURES / "manifest.json").read_text())
    path = tmp_path / "input.enc"
    path.write_bytes((FIXTURES / "sample.enc").read_bytes())
    context = LegacyContext(
        None, input_handler=lambda request: manifest["file_password"]
    )
    with context.open(os.fsencode(path), "rb") as stream:
        assert stream.read() == bytes.fromhex(manifest["plaintext_hex"])
    assert context.path is None
    context.lock()
