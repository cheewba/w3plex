"""Shared fixtures for the new local secret-reference API."""

import pytest

from w3plex.security.memory import ProcessProtection
from w3plex.security.refs import SecretStore
from w3plex.security.storage import CiphertextFile
from w3plex.security.vault import Vault

PASSWORD = b"PUBLIC-TEST-snapshot-password"


@pytest.fixture
def secret_store(tmp_path):
    protection = ProcessProtection()
    protection.activate()
    directory = tmp_path / "secrets"
    directory.mkdir(mode=0o700)
    vault = Vault(CiphertextFile(directory / "vault"), protection=protection)
    vault.create(PASSWORD)
    vault.unlock(PASSWORD)
    yield SecretStore(vault)
    vault.close()
