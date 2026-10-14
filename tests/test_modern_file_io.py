"""Transparent file reading through one owner, with no real secret inputs."""

import base64
import builtins
import io
import json
import os
from pathlib import Path

import pytest

from w3plex.security import EncryptedIOContext, LegacyContext
from w3plex.security.errors import (
    ActivationConflict,
    AuthenticationFailed,
    InteractionRequired,
    InvalidStore,
    PermissionDenied,
    UnsupportedProtection,
)
from w3plex.security.memory import ProcessProtection

FIXTURES = Path(__file__).parent / "fixtures/file-v1"
PASSWORD = "PUBLIC-TEST-file-v1-password"


@pytest.fixture
def context():
    protection = ProcessProtection()
    protection.activate()
    owner = EncryptedIOContext(protection=protection, input_handler=lambda _: PASSWORD)
    try:
        yield owner
    finally:
        owner.close()


def test_binary_text_encoding_newlines_and_name(context):
    source = FIXTURES / "sample.enc"
    manifest = json.loads((FIXTURES / "manifest.json").read_text())
    expected = bytes.fromhex(manifest["plaintext_hex"])
    with context.open(source, "rb") as stream:
        assert stream.read() == expected
        assert stream.name == str(source)
        stream.seek(0)
        assert stream.read(6) == expected[:6]
    with context.open(
        source, "r", encoding="utf-8", errors="replace", newline=""
    ) as stream:
        assert stream.read() == expected.decode("utf-8", errors="replace")
    with context.open(source, "r", encoding="utf-8", errors="replace") as stream:
        assert "\r" not in stream.read()
    with context.open(os.fsencode(source), "rb") as stream:
        assert stream.read() == expected


def test_mixed_legacy_and_modern_reads(context, tmp_path):
    password = PASSWORD
    encrypted, _ = LegacyContext(None).encrypt_data(
        b"\x00\xff legacy\r\n", password=password, add_to_keystore=False
    )
    raw = base64.b64decode(encrypted)
    source = tmp_path / "legacy.enc"
    source.write_bytes(raw)
    with context.open(source, "rb") as stream:
        assert stream.read() == b"\x00\xff legacy\r\n"
    assert (
        context.decrypt_bytes(raw, source=source, password=password)
        == b"\x00\xff legacy\r\n"
    )
    with context.open(FIXTURES / "sample.enc", "rb") as stream:
        assert stream.read()


def test_source_is_closed_and_snapshotted_before_password(tmp_path):
    source = tmp_path / "data.enc"
    raw = (FIXTURES / "sample.enc").read_bytes()
    source.write_bytes(raw)
    handles, requests = [], []

    def opener(*args):
        handle = io.open(*args)  # noqa: UP020, SIM115 -- unpatched opener; context closes it
        handles.append(handle)
        return handle

    def answer(request):
        requests.append(request)
        assert handles[-1].closed
        source.write_bytes(b"replacement")
        return PASSWORD

    protection = ProcessProtection()
    protection.activate()
    owner = EncryptedIOContext(
        protection=protection, input_handler=answer, opener=opener
    )
    try:
        with owner.open(source, "rb") as stream:
            assert stream.read().startswith(b"PUBLIC-TEST-binary-file")
        assert len(requests) == 1 and requests[0].source == source
    finally:
        owner.close()


def test_plain_descriptor_pipe_and_write_modes_are_unchanged(context, tmp_path):
    source = tmp_path / "plain.txt"
    with context.open(source, "w", encoding="utf-8") as stream:
        stream.write("plain")
    with context.open(source, "a", encoding="utf-8") as stream:
        stream.write(" text")
    with context.open(source, "r+") as stream:
        assert stream.read() == "plain text"
    fd = os.open(source, os.O_RDONLY)
    with context.open(fd, "rb") as stream:
        assert stream.read() == b"plain text"
    reader, writer = os.pipe()
    os.write(writer, b"ENC1nonseekable")
    os.close(writer)
    with context.open(reader, "rb") as stream:
        assert stream.read() == b"ENC1nonseekable"


def test_common_and_legacy_contexts_share_exclusive_activation(context, tmp_path):
    legacy = LegacyContext(tmp_path / "absent")
    previous = builtins.open
    with context.activated():
        assert context.active and builtins.open.__self__ is context
        with pytest.raises(ActivationConflict):
            legacy.enable()
        with pytest.raises(ActivationConflict):
            context.enable()
        assert io.open is not builtins.open
    assert not context.active and builtins.open is previous
    with legacy.activated(), pytest.raises(ActivationConflict):
        context.enable()
    assert builtins.open is previous


@pytest.mark.parametrize(
    "raw", [b"W3FILE2\n", b"W3FILE1\ninvalid", b"W3VAULT1\n", b"KS01keystore"]
)
def test_invalid_containers_fail_before_secret_input(tmp_path, raw):
    source = tmp_path / "input.enc"
    source.write_bytes(raw)
    calls = []
    owner = EncryptedIOContext(
        protection=ProcessProtection(),
        input_handler=lambda request: calls.append(request),
    )
    try:
        with pytest.raises(InvalidStore):
            owner.open(source, "rb")
        assert calls == []
    finally:
        owner.close()


def test_missing_protection_or_interaction_never_uses_stdin(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("No ordinary input fallback")

    monkeypatch.setattr(builtins, "input", forbidden)
    source = FIXTURES / "sample.enc"
    owner = EncryptedIOContext(protection=ProcessProtection())
    with pytest.raises(UnsupportedProtection):
        owner.open(source, "rb")
    owner.close()
    protection = ProcessProtection()
    protection.activate()
    owner = EncryptedIOContext(protection=protection)
    try:
        with pytest.raises(InteractionRequired):
            owner.open(source, "rb")
    finally:
        owner.close()


def test_wrong_password_retries_without_returning_plaintext(context):
    requests = []

    def wrong(request):
        requests.append(request)
        return "PUBLIC-TEST-wrong-password"

    context._input = wrong
    with pytest.raises(AuthenticationFailed):
        context.open(FIXTURES / "sample.enc", "rb")
    assert len(requests) == 3 and context._keys == {}


def test_cancel_and_lock_during_password_never_cache_a_key(context):
    def cancelled(request):
        raise KeyboardInterrupt

    context._input = cancelled
    with pytest.raises(KeyboardInterrupt):
        context.open(FIXTURES / "sample.enc", "rb")
    assert context._keys == {}

    def locked(request):
        context.lock()
        return PASSWORD

    context._input = locked
    with pytest.raises(PermissionDenied):
        context.open(FIXTURES / "sample.enc", "rb")
    assert context._keys == {}


def test_available_key_is_reused_and_owned_buffer_is_closed_on_lock(context):
    requests = []
    context._input = lambda request: requests.append(request) or PASSWORD
    source = FIXTURES / "sample.enc"
    with context.open(source, "rb") as stream:
        value = stream.read()
    buffer = next(iter(context._keys.values()))
    with context.open(source, "rb") as stream:
        assert stream.read() == value
    assert len(requests) == 1
    context.lock()
    assert context._keys == {}
    with pytest.raises(UnsupportedProtection):
        buffer.copy_bytes()
    with context.open(source, "rb") as stream:
        assert stream.read() == value
    assert len(requests) == 2
