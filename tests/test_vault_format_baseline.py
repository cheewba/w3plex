"""Fixed encrypted records made before the generic storage refactor."""

import hashlib
import json
from pathlib import Path

from w3plex.security.contracts import SecretKind, SecretUse
from w3plex.security.memory import ProcessProtection
from w3plex.security.storage import CiphertextFile
from w3plex.security.vault import Vault

FIXTURES = Path(__file__).parent / "fixtures/security"


def test_fixed_old_vault_records_remain_readable(tmp_path):
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
        for reference, expected in zip(
            vault.references(), manifest["records"], strict=True
        ):
            assert reference.identifier == expected["id"]
            assert reference.address == expected["address"]
            use = {
                SecretKind.DATA: SecretUse.DECRYPT,
                SecretKind.API: SecretUse.HTTP,
                SecretKind.WALLET: SecretUse.MESSAGE,
            }[reference.kind]
            assert vault._use_secret(reference, use, bytes.hex) == expected["value_hex"]
        assert storage.read()[0] == raw
    finally:
        vault.close()
