"""Pre-0.1 observable behavior through the replacement security API.

Passwords and keys in this file are public, synthetic test values.
"""

import base64
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from w3plex import security
from w3plex.security import io as encryption_io
from w3plex.security.errors import AuthenticationFailed, InvalidStore

FIXTURES = Path(__file__).parent / "fixtures" / "legacy-security"


@pytest.fixture
def legacy(monkeypatch, tmp_path):
    monkeypatch.setenv("W3PLEX_KEYSTORE", str(tmp_path / "store.bin"))
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)

    def password(request):
        prompts = {
            "master": "Master password: ",
            "master_confirm": "Master password confirm: ",
            "file": f"Password for {request.source}: ",
        }
        return encryption_io.request_password(prompts[request.kind])

    context = security.LegacyContext(
        tmp_path / "store.bin", input_handler=password, persist_keys=True
    )
    yield context
    context.lock()


def inputs(monkeypatch, values):
    answers = iter(values)
    prompts = []

    def answer(prompt):
        prompts.append(prompt)
        value = next(answers)
        if isinstance(value, BaseException):
            raise value
        return value

    monkeypatch.setattr(encryption_io.getpass, "getpass", answer)
    return prompts


def encrypted_bytes(legacy, data, password="file"):
    ciphertext, _ = legacy.encrypt_data(data, password=password, add_to_keystore=False)
    return base64.b64decode(ciphertext)


def test_explicit_activation_preserves_custom_plain_opener(tmp_path):
    script = """import builtins, io
calls = []
def custom(*args, **kwargs):
    calls.append(args[0])
    return io.open(*args, **kwargs)
builtins.open = custom
from w3plex.security import enable_encrypted_io, disable_encrypted_io
assert builtins.open is custom
enable_encrypted_io()
calls.clear()
with builtins.open("plain.txt", "w") as stream:
    stream.write("plain")
with builtins.open("plain.txt", "r") as stream:
    assert stream.read() == "plain"
assert calls == ["plain.txt", "plain.txt"]
disable_encrypted_io()
assert builtins.open is custom
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("n", [4096, 8192, 16384, 32768])
def test_fixed_old_keystores_and_ciphertexts(legacy, monkeypatch, n):
    manifest = json.loads((FIXTURES / "manifest.json").read_text())
    for filename, digest in manifest["sha256"].items():
        assert hashlib.sha256((FIXTURES / filename).read_bytes()).hexdigest() == digest
    store = Path(os.environ["W3PLEX_KEYSTORE"])
    store.write_bytes((FIXTURES / f"ks01-{n}.bin").read_bytes())
    before = store.read_bytes()
    prompts = inputs(monkeypatch, [manifest["master_password"]])
    for _ in range(2):
        with legacy.open(FIXTURES / "sample.enc", "rb") as stream:
            assert stream.read() == bytes.fromhex(manifest["plaintext_hex"])
    assert prompts == ["Master password: "]
    assert store.read_bytes() == before


def test_master_confirmation_cache_and_key_deduplication(legacy, monkeypatch):
    prompts = inputs(monkeypatch, ["master", "master"])
    cipher, password = legacy.encrypt_data(
        "hello", password="file", add_to_keystore=True
    )
    assert password == "file"
    assert legacy.decrypt_data(cipher) == "hello"
    store = Path(os.environ["W3PLEX_KEYSTORE"])
    before = store.read_bytes()
    legacy.encrypt_data("hello", password="file", add_to_keystore=True)
    assert store.read_bytes() == before
    assert prompts == ["Master password: ", "Master password confirm: "]
    assert store.read_bytes()[16:20] == b"KS01"
    if os.name == "posix":
        assert store.stat().st_mode & 0o777 == 0o600


def test_master_confirmation_mismatch_and_cancel_leave_no_store(legacy, monkeypatch):
    inputs(monkeypatch, ["first", "second"])
    with pytest.raises(AuthenticationFailed):
        legacy.unlock_keystore()
    store = Path(os.environ["W3PLEX_KEYSTORE"])
    assert not store.exists()
    inputs(monkeypatch, [KeyboardInterrupt()])
    with pytest.raises(KeyboardInterrupt):
        legacy.unlock_keystore()
    assert not store.exists()


def test_wrong_master_does_not_poison_later_unlock(legacy, monkeypatch):
    inputs(monkeypatch, ["master", "master"])
    cipher, _ = legacy.encrypt_data("hello", password="file")
    legacy.lock()
    inputs(monkeypatch, ["wrong"])
    with pytest.raises(AuthenticationFailed):
        legacy.decrypt_data(cipher)
    inputs(monkeypatch, ["master"])
    assert legacy.decrypt_data(cipher) == "hello"


def test_decrypt_without_password_or_store_does_not_request_input(legacy, monkeypatch):
    cipher, _ = legacy.encrypt_data(
        "PUBLIC-TEST", password="file", add_to_keystore=False
    )

    def forbidden(_):
        raise AssertionError("Explicit data decryption must not prompt")

    monkeypatch.setattr(encryption_io.getpass, "getpass", forbidden)
    with pytest.raises(AuthenticationFailed):
        legacy.decrypt_data(cipher, use_keystore=False)
    assert not Path(os.environ["W3PLEX_KEYSTORE"]).exists()


def test_valid_plaintext_store_and_rejection_of_damaged_or_empty_stores(legacy):
    key = b"a" * 32
    from cryptography.fernet import Fernet

    cipher = base64.b64encode(
        b"ENC1" + Fernet(base64.urlsafe_b64encode(key)).encrypt(b"hello")
    ).decode()
    store = Path(os.environ["W3PLEX_KEYSTORE"])
    store.write_bytes(
        b"s" * 16
        + json.dumps({"keys": [base64.urlsafe_b64encode(key).decode()]}).encode()
    )
    assert legacy.decrypt_data(cipher) == "hello"
    for raw in [b"", b"not-json", b"{}"]:
        legacy.lock()
        store.write_bytes(b"s" * 16 + raw)
        with pytest.raises(InvalidStore):
            legacy.decrypt_data(cipher)
        assert store.read_bytes() == b"s" * 16 + raw
    legacy.lock()
    store.write_bytes(b"short")
    with pytest.raises(InvalidStore):
        legacy.decrypt_data(cipher)


def test_file_password_is_prompted_then_cached_and_persisted(
    legacy, monkeypatch, tmp_path
):
    path = tmp_path / "encrypted"
    path.write_bytes(encrypted_bytes(legacy, b"hello"))
    prompts = inputs(monkeypatch, ["file", "master", "master"])
    for _ in range(2):
        with legacy.open(path) as stream:
            assert stream.read() == "hello"
            assert stream.name == str(path)
    assert prompts == [
        f"Password for {path}: ",
        "Master password: ",
        "Master password confirm: ",
    ]
    legacy.lock()
    prompts = inputs(monkeypatch, ["master"])
    with legacy.open(path) as stream:
        assert stream.read() == "hello"
    assert prompts == ["Master password: "]


def test_three_password_attempts_and_cancel(legacy, monkeypatch, tmp_path, capsys):
    path = tmp_path / "encrypted"
    path.write_bytes(encrypted_bytes(legacy, b"hello"))
    prompts = inputs(monkeypatch, ["wrong", "wrong", "wrong"])
    with pytest.raises(AuthenticationFailed):
        legacy.open(path)
    assert len(prompts) == 3
    output = capsys.readouterr().out
    assert "2 attempts left" in output
    assert "1 attempts left" in output
    assert not Path(os.environ["W3PLEX_KEYSTORE"]).exists()
    inputs(monkeypatch, [KeyboardInterrupt()])
    with pytest.raises(KeyboardInterrupt):
        legacy.open(path)


def test_failed_keystore_replacement_preserves_old_data(legacy, monkeypatch):
    inputs(monkeypatch, ["master", "master"])
    first, _ = legacy.encrypt_data("hello", password="first")
    store = Path(os.environ["W3PLEX_KEYSTORE"])
    before = store.read_bytes()

    def fail(*args, **kwargs):
        raise OSError("PUBLIC-TEST-write-failure")

    monkeypatch.setattr(os, "replace", fail)
    with pytest.raises(OSError, match="PUBLIC-TEST-write-failure"):
        legacy.encrypt_data("second", password="second")
    assert store.read_bytes() == before
    assert sorted(file.name for file in store.parent.iterdir()) == [store.name]
    inputs(monkeypatch, ["master"])
    assert legacy.decrypt_data(first) == "hello"


def test_read_only_context_preserves_legacy_import_then_allows_explicit_save(tmp_path):
    context = security.LegacyContext(None, input_handler=lambda _: "file")
    encoded, _ = context.encrypt_data("hello", password="file", add_to_keystore=False)
    assert context.decrypt_bytes(base64.b64decode(encoded), source="input") == b"hello"
    store = tmp_path / "keys"
    context.path = store
    assert not store.exists()
    context.encrypt_data("hello", password="file", add_to_keystore=True)
    assert store.exists()
    context.lock()
    assert context.decrypt_data(encoded) == "hello"


def test_encryption_helpers_return_types_destinations_and_errors(
    legacy, monkeypatch, tmp_path
):
    source = tmp_path / "plain.txt"
    source.write_bytes(b"hello")
    encrypted = legacy.encrypt_file(source, password="file")
    assert encrypted == source.with_suffix(".txt.enc")
    assert legacy.decrypt_file(encrypted, password="file").read_bytes() == b"hello"
    assert source.read_bytes() == b"hello"
    with pytest.raises(ValueError, match="already encrypted"):
        legacy.encrypt_file(encrypted, password="file")
    with pytest.raises(ValueError, match="not encrypted"):
        legacy.decrypt_file(source, password="file")
    destination = tmp_path / "chosen"
    assert legacy.encrypt_file(source, password="file", dst=destination) == destination
    assert (
        legacy.decrypt_file(destination, password="file", inplace=True) == destination
    )
    assert destination.read_bytes() == b"hello"
    with pytest.raises(ValueError, match="Either password"):
        legacy.encrypt_data("hello", add_to_keystore=False)
    inputs(monkeypatch, ["master", "master"])
    ciphertext, password = legacy.encrypt_data("hello")
    assert isinstance(password, str) and password
    assert isinstance(ciphertext, str)
    assert legacy.decrypt_data(ciphertext, password=password) == "hello"
    plaintext = base64.b64encode(b"plain").decode()
    assert legacy.decrypt_data(plaintext) == plaintext
    with pytest.raises(ValueError, match="base64"):
        legacy.decrypt_data("non-ascii: é")


@pytest.mark.parametrize("encrypted", [False, True])
def test_encoding_errors_newlines_binary_and_name(legacy, tmp_path, encrypted):
    raw = b"caf\xe9\r\nnext\rfinal\n"
    path = tmp_path / "sample"
    path.write_bytes(encrypted_bytes(legacy, raw) if encrypted else raw)
    legacy.install_keys([hashlib.sha256(b"file").digest()])
    with legacy.open(path, encoding="latin-1", newline="") as stream:
        assert stream.read() == "café\r\nnext\rfinal\n"
        assert stream.name == str(path)
    with legacy.open(path, encoding="latin-1") as stream:
        assert stream.read() == "café\nnext\nfinal\n"
    with legacy.open(path, encoding="ascii", errors="replace") as stream:
        assert "caf�" in stream.read()
    with (
        legacy.open(path, encoding="ascii", errors="strict") as stream,
        pytest.raises(UnicodeDecodeError),
    ):
        stream.read()
    with legacy.open(path, "rb") as stream:
        assert stream.read() == raw


def test_descriptor_nonseekable_and_write_modes_are_untouched(legacy, tmp_path):
    path = tmp_path / "sample"
    raw = encrypted_bytes(legacy, b"hello")
    path.write_bytes(raw)
    descriptor = os.open(path, os.O_RDONLY)
    with legacy.open(descriptor, "rb", closefd=False) as stream:
        assert stream.read() == raw
    os.close(descriptor)
    read_fd, write_fd = os.pipe()
    os.write(write_fd, raw)
    os.close(write_fd)
    with legacy.open(read_fd, "rb") as stream:
        assert not stream.seekable()
        assert stream.read() == raw
    with legacy.open(path, "r+b") as stream:
        assert stream.read() == raw
    with legacy.open(path, "ab") as stream:
        stream.write(b"tail")
    assert path.read_bytes() == raw + b"tail"
    with legacy.open(path, "wb") as stream:
        stream.write(b"replacement")
    assert path.read_bytes() == b"replacement"


def test_noninteractive_standalone_password_never_falls_back_to_echo(
    legacy, monkeypatch
):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)

    def forbidden(_):
        raise AssertionError("getpass fallback must not run")

    monkeypatch.setattr(encryption_io.getpass, "getpass", forbidden)
    from w3plex.security.errors import InteractionRequired

    with pytest.raises(InteractionRequired):
        legacy.unlock_keystore()
    assert not Path(os.environ["W3PLEX_KEYSTORE"]).exists()


@pytest.mark.parametrize("persist_keys", [False, True])
def test_encryption_limits_preserve_files_and_store(
    tmp_path, monkeypatch, persist_keys
):
    from w3plex.security import legacy as legacy_format
    from w3plex.security.errors import InvalidStore

    def forbidden(_):
        raise AssertionError("Over-limit writes must fail before requesting a password")

    store = tmp_path / "keys"
    context = security.LegacyContext(
        store, input_handler=forbidden, persist_keys=persist_keys
    )
    context.install_keys([b"a" * 32] * 4096)
    with pytest.raises(InvalidStore):
        context.encrypt_data("PUBLIC-TEST", password="file", add_to_keystore=True)
    assert not store.exists()
    source, destination = tmp_path / "input", tmp_path / "output"
    source.write_text("PUBLIC-TEST-input")
    destination.write_text("PUBLIC-TEST-previous-output")
    monkeypatch.setattr(legacy_format, "_MAX_FILE", 8)
    with pytest.raises(InvalidStore):
        context.encrypt_file(source, password="file", dst=destination)
    assert source.read_text() == "PUBLIC-TEST-input"
    assert destination.read_text() == "PUBLIC-TEST-previous-output"
    assert not store.exists()
