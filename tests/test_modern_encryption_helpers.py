"""Default modern helpers and CLI with synthetic inputs and private storage."""

import base64
import os
import subprocess
import sys

import pytest

from w3plex.security import EncryptedIOContext, LegacyContext, file_format
from w3plex.security.errors import (
    AuthenticationFailed,
    PermissionDenied,
    UnsupportedProtection,
)
from w3plex.security.storage import StoreChanged, UnsafeStorage

PASSWORD = "PUBLIC-TEST-file-password"
MASTER = "PUBLIC-TEST-modern-master"


@pytest.fixture
def owner(tmp_path):
    context = EncryptedIOContext(
        keystore_path=tmp_path / "private" / "keys.vault",
        input_handler=lambda request: PASSWORD if request.kind == "file" else MASTER,
    )
    try:
        yield context
    finally:
        context.close()


def test_file_helpers_preserve_returns_contents_and_destination_rules(owner, tmp_path):
    source = tmp_path / "input.bin"
    value = b"\x00\xff\xfePUBLIC-TEST\r\n"
    source.write_bytes(value)
    encrypted = owner.encrypt_file(source, password=PASSWORD)
    assert encrypted == source.with_suffix(".bin.enc")
    assert encrypted.read_bytes().startswith(file_format.MAGIC)
    assert encrypted.stat().st_mode & 0o777 == 0o600
    decoded = owner.decrypt_file(encrypted, password=PASSWORD)
    assert decoded == encrypted.with_suffix(".dec") and decoded.read_bytes() == value
    assert decoded.stat().st_mode & 0o777 == 0o600 and source.read_bytes() == value
    chosen = tmp_path / "chosen"
    chosen.write_text("previous output")
    assert owner.encrypt_file(source, password=PASSWORD, dst=chosen) == chosen
    assert owner.decrypt_file(chosen, password=PASSWORD, inplace=True) == chosen
    assert chosen.read_bytes() == value
    assert owner.encrypt_file(source, password=PASSWORD, inplace=True) == source
    assert owner.decrypt_file(source, password=PASSWORD, inplace=True) == source
    assert source.read_bytes() == value
    with pytest.raises(ValueError, match="not encrypted"):
        owner.decrypt_file(source, password=PASSWORD)
    owner.encrypt_file(source, password=PASSWORD, inplace=True)
    with pytest.raises(ValueError, match="already encrypted"):
        owner.encrypt_file(source, password=PASSWORD)


def test_binary_legacy_decryption_still_works_through_modern_helper(owner, tmp_path):
    value = b"\xff\x00PUBLIC-TEST-legacy"
    encoded, _ = LegacyContext(None).encrypt_data(
        value, password=PASSWORD, add_to_keystore=False
    )
    source = tmp_path / "legacy.enc"
    original = base64.b64decode(encoded)
    source.write_bytes(original)
    decoded = owner.decrypt_file(source, password=PASSWORD)
    assert decoded.read_bytes() == value and source.read_bytes() == original


def test_data_helpers_use_modern_base64_and_remember_generated_password(owner):
    encrypted, password = owner.encrypt_data("PUBLIC-TEST-hello 世界")
    assert password and base64.b64decode(encrypted).startswith(file_format.MAGIC)
    assert owner.decrypt_data(encrypted) == "PUBLIC-TEST-hello 世界"
    assert (
        owner.decrypt_data(encrypted, password=password, use_keystore=False)
        == "PUBLIC-TEST-hello 世界"
    )
    encoded, _ = owner.encrypt_data(
        "PUBLIC-TEST", password=PASSWORD, add_to_keystore=False
    )
    with pytest.raises(AuthenticationFailed):
        owner.decrypt_data(encoded, use_keystore=False)
    plain = base64.b64encode(b"plain").decode()
    assert owner.decrypt_data(plain) == plain
    with pytest.raises(ValueError, match="base64"):
        owner.decrypt_data("not valid é")
    with pytest.raises(ValueError, match="Either password"):
        owner.encrypt_data("PUBLIC-TEST", add_to_keystore=False)


def test_wrong_password_preserves_both_files_and_creates_no_plaintext_temporary(
    owner, tmp_path
):
    source = tmp_path / "input"
    source.write_text("PUBLIC-TEST-private-value")
    encrypted = owner.encrypt_file(source, password=PASSWORD)
    output = tmp_path / "decoded"
    output.write_text("PUBLIC-TEST-existing")
    with pytest.raises(AuthenticationFailed):
        owner.decrypt_file(encrypted, password="PUBLIC-TEST-wrong", dst=output)
    assert output.read_text() == "PUBLIC-TEST-existing"
    assert source.read_text() == "PUBLIC-TEST-private-value"
    assert not list(tmp_path.glob("*.tmp"))


@pytest.mark.parametrize("point", ["file-sync", "replace", "directory-sync"])
def test_interrupted_ciphertext_commit_keeps_complete_source_or_ciphertext(
    owner, tmp_path, monkeypatch, point
):
    source = tmp_path / "input"
    original = b"PUBLIC-TEST-private-value"
    source.write_bytes(original)
    sync = os.fsync
    calls = 0

    def fsync(fd):
        nonlocal calls
        calls += 1
        if (point == "file-sync" and calls == 1) or (
            point == "directory-sync" and calls == 2
        ):
            raise OSError("PUBLIC-TEST-write-failure")
        return sync(fd)

    def replace(*args, **kwargs):
        raise OSError("PUBLIC-TEST-write-failure")

    monkeypatch.setattr(os, "fsync", fsync)
    if point == "replace":
        monkeypatch.setattr(os, "replace", replace)
    with pytest.raises(OSError):
        owner.encrypt_file(source, password=PASSWORD, inplace=True)
    raw = source.read_bytes()
    if point == "directory-sync":
        assert (
            owner.decrypt_bytes(
                raw, source=source, password=PASSWORD, use_keystore=False
            )
            == original
        )
    else:
        assert raw == original
    assert not list(tmp_path.glob("*.tmp"))


def test_destination_change_during_input_is_rejected(owner, tmp_path):
    source, destination = tmp_path / "source", tmp_path / "out"
    source.write_text("PUBLIC-TEST-input")
    destination.write_text("PUBLIC-TEST-before")

    def password(request):
        destination.write_text("PUBLIC-TEST-changed")
        return PASSWORD

    owner._input = password
    with pytest.raises(StoreChanged):
        owner.encrypt_file(source, dst=destination)
    assert destination.read_text() == "PUBLIC-TEST-changed"


def test_lock_during_input_prevents_output(owner, tmp_path):
    source = tmp_path / "input"
    source.write_text("PUBLIC-TEST-input")

    def password(request):
        owner.lock()
        return PASSWORD

    owner._input = password
    with pytest.raises(PermissionDenied):
        owner.encrypt_file(source)
    assert not source.with_suffix(".enc").exists()
    assert not (tmp_path / "private" / "keys.vault").exists()


@pytest.mark.parametrize("mode", [0o755, 0o777])
def test_external_file_permissions_are_left_to_the_application(owner, tmp_path, mode):
    directory = tmp_path / "accessible"
    directory.mkdir()
    directory.chmod(mode)
    source = directory / "input"
    source.write_text("PUBLIC-TEST-value")
    output = owner.encrypt_file(source, password=PASSWORD)
    assert output.stat().st_mode & 0o777 == 0o600
    assert directory.stat().st_mode & 0o777 == mode
    output.chmod(0o644)
    assert (
        owner.decrypt_file(output, password=PASSWORD).read_text() == "PUBLIC-TEST-value"
    )
    assert output.stat().st_mode & 0o777 == 0o644


@pytest.mark.parametrize("alias", ["symlink", "hardlink"])
def test_output_aliases_are_rejected_before_password(owner, tmp_path, alias):
    source, target, output = (
        tmp_path / "source",
        tmp_path / "target",
        tmp_path / "output",
    )
    source.write_text("PUBLIC-TEST-source")
    target.write_text("PUBLIC-TEST-target")
    if alias == "symlink":
        output.symlink_to(target)
    else:
        os.link(target, output)
    owner._input = lambda _: pytest.fail("Unsafe output requested a password")
    with pytest.raises(UnsafeStorage):
        owner.encrypt_file(source, dst=output)
    assert target.read_text() == "PUBLIC-TEST-target"


def test_owned_context_import_and_plain_reads_do_not_activate_process_controls(
    tmp_path,
):
    script = """import builtins, resource, sys
from pathlib import Path
before = resource.getrlimit(resource.RLIMIT_CORE)
previous = builtins.open
from w3plex.security import enable_encrypted_io, disable_encrypted_io
assert builtins.open is previous
context = enable_encrypted_io()
with open(sys.argv[1]) as stream:
    assert stream.read() == "PUBLIC-TEST-plain"
assert resource.getrlimit(resource.RLIMIT_CORE) == before
disable_encrypted_io()
assert builtins.open is previous
"""
    source = tmp_path / "plain"
    source.write_text("PUBLIC-TEST-plain")
    result = subprocess.run(
        [sys.executable, "-c", script, str(source)],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_default_helpers_and_cli_activation_open_modern_files(tmp_path):
    script = """import builtins, getpass, os, sys
from pathlib import Path
os.environ["W3PLEX_KEYSTORE"] = str(Path(sys.argv[1]) / "store")
os.environ.pop("W3PLEX_SECRET_STORE", None)
from w3plex.security import encrypt_file
source = Path(sys.argv[1]) / "input"
source.write_text("PUBLIC-TEST-modern")
path = encrypt_file(source, password="PUBLIC-TEST-file")
assert path.read_bytes().startswith(b"W3FILE1\\n")
answers = iter(["PUBLIC-TEST-master", "PUBLIC-TEST-master"])
sys.stdin.isatty = lambda: True
getpass.getpass = lambda _: next(answers)
from w3plex.main import process_args
process_args(["--help"])
with open(path) as stream:
    assert stream.read() == "PUBLIC-TEST-modern"
assert not (Path(sys.argv[1]) / "legacy").exists()
assert (Path(sys.argv[1]) / "store").exists()
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(tmp_path)],
        capture_output=True,
        text=True,
        timeout=25,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_required_protection_is_checked_before_explicit_cli_input(owner, monkeypatch):
    def unavailable():
        raise UnsupportedProtection()

    monkeypatch.setattr(owner._protection, "activate", unavailable)
    owner._input = lambda _: pytest.fail("Input happened without protection")
    with pytest.raises(UnsupportedProtection):
        owner.file_password("input")
