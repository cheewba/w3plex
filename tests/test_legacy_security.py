"""Characterization tests written before changing revision 5acf2761.

Passwords and keys in this file are public, synthetic test values.
"""

import base64
import builtins
import hashlib
import importlib
import io
import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures" / "legacy-security"


@pytest.fixture
def legacy(monkeypatch, tmp_path):
    previous = builtins.open
    module = importlib.import_module("w3plex.secure")
    # Do not change the pytest process's opener during characterization.
    builtins.open = previous
    monkeypatch.setattr(module, "_orig_open", previous)
    monkeypatch.setattr(module, "_KEYSTORE_PATH", tmp_path / "store.bin")
    monkeypatch.setattr(module, "_salt", None)
    monkeypatch.setattr(module, "_master_key", None)
    monkeypatch.setattr(module, "_SCRYPT_WORK", None)
    monkeypatch.setattr(module, "_SCRYPT_N", 2**12)
    return module


def inputs(monkeypatch, legacy, values):
    answers = iter(values)
    prompts = []

    def answer(prompt):
        prompts.append(prompt)
        value = next(answers)
        if isinstance(value, BaseException):
            raise value
        return value

    monkeypatch.setattr(legacy.getpass, "getpass", answer)
    return prompts


@pytest.mark.parametrize("n", [2**12, 2**13, 2**14, 2**15])
def test_fixed_old_keystores_and_ciphertexts(legacy, monkeypatch, n):
    manifest = json.loads((FIXTURES / "manifest.json").read_text())
    for filename, digest in manifest["sha256"].items():
        assert hashlib.sha256((FIXTURES / filename).read_bytes()).hexdigest() == digest
    legacy._KEYSTORE_PATH.write_bytes((FIXTURES / f"ks01-{n}.bin").read_bytes())
    monkeypatch.setattr(legacy, "_SCRYPT_N", n)
    # KS01 omitted the work settings. Supply enough OpenSSL memory to read each
    # known setting, without changing its password, salt or KDF computation.
    monkeypatch.setattr(
        legacy,
        "scrypt",
        lambda *a, **kw: hashlib.scrypt(*a, **kw, maxmem=128 * 1024 * 1024),
    )
    prompts = inputs(monkeypatch, legacy, [manifest["master_password"]])
    with legacy._secure_open(FIXTURES / "sample.enc", "rb") as stream:
        assert stream.read() == bytes.fromhex(manifest["plaintext_hex"])
    assert prompts == ["Master password: "]


def test_master_confirmation_cache_and_key_deduplication(legacy, monkeypatch):
    prompts = inputs(monkeypatch, legacy, ["master", "master"])
    cipher, password = legacy.encrypt_data(
        "hello", password="file", add_to_keystore=True
    )
    assert password == "file"
    assert legacy.decrypt_data(cipher) == "hello"
    legacy._add_key(legacy._derive_file_key("file"))
    assert len(legacy._all_keys()) == 1
    assert prompts == ["Master password: ", "Master password confirm: "]
    assert legacy._KEYSTORE_PATH.read_bytes()[16:20] == b"KS01"


def test_master_confirmation_mismatch_and_cancel_leave_no_store(legacy, monkeypatch):
    inputs(monkeypatch, legacy, ["first", "second"])
    with pytest.raises(legacy.IncorrectPassword, match="don't match"):
        legacy.unlock_keystore()
    assert legacy._master_key is None
    assert not legacy._KEYSTORE_PATH.exists()
    inputs(monkeypatch, legacy, [KeyboardInterrupt()])
    with pytest.raises(KeyboardInterrupt):
        legacy.unlock_keystore()
    assert not legacy._KEYSTORE_PATH.exists()


def test_wrong_master_resets_cached_key(legacy, monkeypatch):
    inputs(monkeypatch, legacy, ["master", "master"])
    legacy._add_key(legacy._derive_file_key("file"))
    legacy._master_key = None
    inputs(monkeypatch, legacy, ["wrong"])
    with pytest.raises(legacy.IncorrectPassword, match="master"):
        legacy._all_keys()
    assert legacy._master_key is None
    inputs(monkeypatch, legacy, ["master"])
    assert legacy._all_keys() == [legacy._derive_file_key("file")]


def test_plaintext_damaged_and_empty_legacy_stores(legacy):
    key = base64.urlsafe_b64encode(b"a" * 32).decode()
    legacy._KEYSTORE_PATH.write_bytes(b"s" * 16 + json.dumps({"keys": [key]}).encode())
    assert legacy._all_keys() == [b"a" * 32]
    assert legacy._master_key is None
    for raw in [b"", b"not-json", b"{}"]:
        legacy._KEYSTORE_PATH.write_bytes(b"s" * 16 + raw)
        assert legacy._load_keystore() == []
    legacy._KEYSTORE_PATH.write_bytes(b"short")
    with pytest.raises(ValueError, match="corrupt"):
        legacy._load_keystore()


def test_file_password_is_prompted_then_cached(legacy, monkeypatch, tmp_path):
    path = tmp_path / "encrypted"
    path.write_bytes(legacy._encrypt_bytes(b"hello", "file"))
    prompts = inputs(monkeypatch, legacy, ["file", "master", "master"])
    for _ in range(2):
        with legacy._secure_open(path) as stream:
            assert stream.read() == "hello"
            assert stream.name == str(path)
    assert prompts == [
        f"Password for {path}: ",
        "Master password: ",
        "Master password confirm: ",
    ]


def test_three_password_attempts_and_cancel(legacy, monkeypatch, tmp_path):
    path = tmp_path / "encrypted"
    path.write_bytes(legacy._encrypt_bytes(b"hello", "file"))
    output = io.StringIO()
    monkeypatch.setattr(legacy, "stdout", output)
    prompts = inputs(monkeypatch, legacy, ["wrong", "wrong", "wrong"])
    with pytest.raises(legacy.IncorrectPassword):
        legacy._secure_open(path)
    assert len(prompts) == 3
    assert "2 attempts left" in output.getvalue()
    assert "1 attempts left" in output.getvalue()
    assert not legacy._KEYSTORE_PATH.exists()
    inputs(monkeypatch, legacy, [KeyboardInterrupt()])
    with pytest.raises(KeyboardInterrupt):
        legacy._secure_open(path)


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
    monkeypatch.setattr(legacy.secrets, "token_urlsafe", lambda n: "generated")
    inputs(monkeypatch, legacy, ["master", "master"])
    ciphertext, password = legacy.encrypt_data("hello")
    assert password == "generated"
    assert isinstance(ciphertext, str)
    assert legacy.decrypt_data(ciphertext, password=password) == "hello"
    assert (
        legacy.decrypt_data(base64.b64encode(b"plain").decode())
        == base64.b64encode(b"plain").decode()
    )
    with pytest.raises(ValueError, match="base64"):
        legacy.decrypt_data("non-ascii: \u00e9")
