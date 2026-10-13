"""Generic storage preserves historical ciphertext and arbitrary data."""

import hashlib
import json
from pathlib import Path

import pytest

from w3plex.security import SecretStore
from w3plex.security.errors import InvalidStore
from w3plex.security.memory import ProcessProtection
from w3plex.security.storage import CiphertextFile
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
