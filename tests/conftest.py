"""Shared native protection and caller-owned vault lifetime."""

import pytest

from w3plex.security.memory import ProcessProtection
from w3plex.security.refs import SecretStore
from w3plex.security.storage import CiphertextFile
from w3plex.security.vault import Vault


@pytest.fixture
def vault_password():
    return b"PUBLIC-TEST-snapshot-password"


@pytest.fixture
def protection():
    protection = ProcessProtection()
    protection.activate()
    return protection


@pytest.fixture
def vault(tmp_path, protection, vault_password):
    directory = tmp_path / "secrets"
    directory.mkdir(mode=0o700)
    vault = Vault(CiphertextFile(directory / "vault"), protection=protection)
    try:
        vault.create(vault_password)
        vault.unlock(vault_password)
        yield vault
    finally:
        vault.close()


@pytest.fixture
def secret_store(vault):
    return SecretStore(vault)
