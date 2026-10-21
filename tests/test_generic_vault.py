"""Generic storage preserves historical ciphertext and arbitrary data."""

import hashlib
import json
from pathlib import Path

import pytest

from w3plex.security import SecretStore
from w3plex.security.errors import InvalidStore, PermissionDenied
from w3plex.security.memory import ProcessProtection
from w3plex.security.storage import CiphertextFile, StoreChanged
from w3plex.security.vault import Vault

FIXTURES = Path(__file__).parent / "fixtures/security"


def test_generic_vault_reads_fixed_old_records_without_rewriting(tmp_path):
    manifest = json.loads((FIXTURES / "vault-v1.json").read_text())
    raw = (FIXTURES / "vault-v1.bin").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == manifest["sha256"]
    protection = ProcessProtection()
    protection.activate()
    storage = CiphertextFile(tmp_path / "vault")
    storage.write(raw, expected=None)
    vault = Vault(storage, protection=protection)
    try:
        vault.unlock(manifest["password"].encode())
        store = SecretStore(vault)
        assert vault.identifiers() == tuple(item["id"] for item in manifest["records"])
        for item in manifest["records"]:
            assert (
                store.reference(item["id"]).ref(silent=True).hex() == item["value_hex"]
            )
            assert vault.metadata(item["id"])["kind"] == item["kind"]
        assert storage.read()[0] == raw
        assert not hasattr(vault, "wallets")
        assert not hasattr(vault, "read_secret")
    finally:
        vault.close()


def test_generic_metadata_has_no_wallet_validation(secret_store):
    vault = secret_store._vault
    identifier = vault.save(
        b"any data", metadata={"format": "custom", "kind": "anything"}
    )
    assert vault.read(identifier) == b"any data"
    assert vault.metadata(identifier) == {"format": "custom", "kind": "anything"}
    raw = vault._storage.read()[0]
    with pytest.raises(InvalidStore):
        vault.save(b"value", metadata={"id": "0" * 32})
    assert vault._storage.read()[0] == raw


def test_invalid_generic_batch_commits_nothing(secret_store):
    vault = secret_store._vault
    original = vault._storage.read()[0]
    with pytest.raises(InvalidStore):
        vault.import_entries([(b"valid", {}), ("invalid", {})])
    assert vault._storage.read()[0] == original


def test_independent_unlocked_owners_cache_reads_and_refuse_stale_append(secret_store):
    vault = secret_store._vault
    first = vault.save(b"PUBLIC-TEST-first", metadata={"tag": [1, "synthetic"]})
    other = Vault(CiphertextFile(vault.path), protection=vault.protection)
    try:
        other.unlock(b"PUBLIC-TEST-snapshot-password")
        checkpoint = other.checkpoint()
        second = vault.save(b"PUBLIC-TEST-second")
        assert other.identifiers() == (first,)
        assert other.read(first) == b"PUBLIC-TEST-first"
        assert other.metadata(first) == {"tag": [1, "synthetic"]}
        assert other.checkpoint() == checkpoint
        with pytest.raises(PermissionDenied):
            other.read(second)
        committed = vault.path.read_bytes()
        with pytest.raises(StoreChanged):
            other.save(b"PUBLIC-TEST-stale")
        assert not other.is_unlocked and vault.is_unlocked
        assert vault.path.read_bytes() == committed
        other.unlock(b"PUBLIC-TEST-snapshot-password")
        assert other.identifiers() == (first, second)
    finally:
        other.close()


def test_password_rotation_preserves_records_and_changes_data_key(secret_store):
    from w3plex.security import vault_format as codec

    vault = secret_store._vault
    identifier = vault.save(b"PUBLIC-TEST-value", metadata={"source": "synthetic"})
    before = codec.parse(vault.path.read_bytes())
    old_key = codec.unwrap(before, b"PUBLIC-TEST-snapshot-password")
    plaintext = codec.open_payload(before, old_key)
    vault.change_password(b"PUBLIC-TEST-snapshot-password", b"PUBLIC-TEST-replacement")
    after = codec.parse(vault.path.read_bytes())
    new_key = codec.unwrap(after, b"PUBLIC-TEST-replacement")
    assert new_key != old_key and before.wrapped_key != after.wrapped_key
    assert before.header["store_id"] == after.header["store_id"]
    assert codec.open_payload(after, new_key) == plaintext
    assert not vault.is_unlocked
    vault.unlock(b"PUBLIC-TEST-replacement")
    assert vault.read(identifier) == b"PUBLIC-TEST-value"
