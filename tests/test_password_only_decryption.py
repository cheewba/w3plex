"""An explicit file password never requests access to the selected key store."""

import base64
import json
from pathlib import Path

import pytest

from w3plex.security import EncryptedIOContext, file_format, io as encryption_io
from w3plex.security.errors import AuthenticationFailed
from w3plex.security.memory import ProcessProtection
from w3plex.security.storage import CiphertextFile
from w3plex.security.vault import Vault

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(params=["modern", "legacy"], scope="module")
def encrypted_sample(request):
    directory = FIXTURES / (
        "file-v1" if request.param == "modern" else "legacy-security"
    )
    manifest = json.loads((directory / "manifest.json").read_text())
    if request.param == "modern":
        value = b"PUBLIC-TEST-password-only-text"
        password = manifest["password"]
        envelope, _ = file_format.seal(value, password.encode())
        return envelope.serialize(), password, value
    return (
        (directory / "sample.enc").read_bytes(),
        manifest["password" if request.param == "modern" else "file_password"],
        bytes.fromhex(manifest["plaintext_hex"]),
    )


@pytest.mark.parametrize("store_kind", ["modern", "legacy", "broken", "missing"])
@pytest.mark.parametrize("operation", ["data", "bytes", "file"])
def test_supplied_password_bypasses_selected_store(
    tmp_path, encrypted_sample, store_kind, operation
):
    raw, password, value = encrypted_sample
    selected = tmp_path / "selected"
    original = (
        (FIXTURES / "vault-v1/sample.vault").read_bytes()
        if store_kind == "modern"
        else (FIXTURES / "legacy-security/ks01-4096.bin").read_bytes()
        if store_kind == "legacy"
        else b"PUBLIC-TEST-corrupt-store"
        if store_kind == "broken"
        else None
    )
    if original is not None:
        selected.write_bytes(original)
    owner = EncryptedIOContext(
        keystore_path=selected,
        legacy_keystore_path=selected,
        persist_keys=True,
    )
    try:
        if operation == "data":
            assert (
                owner.decrypt_data(base64.b64encode(raw).decode(), password=password)
                == value.decode()
            )
        elif operation == "bytes":
            assert owner.decrypt_bytes(raw, source="sample", password=password) == value
        else:
            source = tmp_path / "sample.enc"
            source.write_bytes(raw)
            output = owner.decrypt_file(source, password=password, use_keystore=True)
            assert output.read_bytes() == value and source.read_bytes() == raw
        assert (selected.read_bytes() if selected.exists() else None) == original
        assert not selected.with_name(selected.name + ".legacy.bak").exists()
        assert not selected.with_name("." + selected.name + ".lock").exists()
    finally:
        owner.close()


def test_wrong_supplied_password_never_unlocks_selected_store(
    tmp_path, encrypted_sample
):
    raw, _, _ = encrypted_sample
    path = tmp_path / "selected"
    original = (FIXTURES / "vault-v1/sample.vault").read_bytes()
    path.write_bytes(original)
    owner = EncryptedIOContext(keystore_path=path, persist_keys=True)
    try:
        with pytest.raises(AuthenticationFailed):
            owner.decrypt_data(
                base64.b64encode(raw).decode(), password="PUBLIC-TEST-wrong"
            )
        assert path.read_bytes() == original
        assert list(tmp_path.iterdir()) == [path]
    finally:
        owner.close()


def test_supplied_password_bypasses_borrowed_locked_vault(tmp_path, encrypted_sample):
    raw, password, value = encrypted_sample
    selected = tmp_path / "selected"
    original = (FIXTURES / "vault-v1/sample.vault").read_bytes()
    selected.write_bytes(original)
    protection = ProcessProtection()
    protection.activate()
    vault = Vault(CiphertextFile(selected), protection=protection)
    owner = EncryptedIOContext(protection=protection, keystore=vault, persist_keys=True)
    try:
        assert (
            owner.decrypt_data(base64.b64encode(raw).decode(), password=password)
            == value.decode()
        )
        assert not vault.is_unlocked
        assert selected.read_bytes() == original and list(tmp_path.iterdir()) == [
            selected
        ]
    finally:
        owner.close()
        vault.close()


def test_default_password_helper_needs_no_terminal(
    tmp_path, monkeypatch, encrypted_sample
):
    raw, password, value = encrypted_sample
    selected = tmp_path / "selected"
    original = (FIXTURES / "vault-v1/sample.vault").read_bytes()
    selected.write_bytes(original)
    monkeypatch.setenv("W3PLEX_KEYSTORE", str(selected))
    monkeypatch.delenv("W3PLEX_SECRET_STORE", raising=False)
    monkeypatch.setattr(encryption_io, "_CONTEXT", None)
    try:
        assert (
            encryption_io.decrypt_data(
                base64.b64encode(raw).decode(), password=password
            )
            == value.decode()
        )
        assert selected.read_bytes() == original
        assert list(tmp_path.iterdir()) == [selected]
    finally:
        encryption_io.default_context().close()
