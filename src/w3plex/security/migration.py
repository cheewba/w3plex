"""Automatic conversion of captured legacy file keys with recoverable backups."""

import base64
import secrets
from collections.abc import Callable
from pathlib import Path

from . import file_format, vault_format
from .errors import AuthenticationFailed, InvalidStore
from .legacy import decode_keystore
from .memory import LockedBuffer, ProcessProtection
from .storage import CiphertextFile, StoreChanged
from .vault import Vault


def migrate_keystore(
    storage: CiphertextFile,
    backup: Path,
    *,
    protection: ProcessProtection,
    password: Callable[[str, Path], str],
    check: Callable[[], None],
) -> Vault:
    raw, identity = storage.read()

    def unchanged():
        check()
        if storage.identity() != identity:
            raise StoreChanged()

    if raw.startswith(b"W3VAULT"):
        vault_format.parse(raw)
        vault = Vault(storage, protection=protection)
        try:
            vault.unlock(password("master", storage.path).encode())
            unchanged()
            return vault
        except BaseException:
            vault.close()
            raise
    if len(raw) > 1024 * 1024 or len(raw) < 16:
        raise InvalidStore()
    encrypted = raw[16:20] == b"KS01"
    if not encrypted:
        decode_keystore(raw)
    if backup == storage.path:
        raise StoreChanged()
    unchanged()
    entered = password("master", storage.path)
    unchanged()
    if not encrypted:
        if password("master_confirm", storage.path) != entered:
            raise AuthenticationFailed()
        unchanged()
    keys = decode_keystore(raw, entered)
    records = [
        {
            "id": secrets.token_hex(16),
            "value": base64.b64encode(key).decode("ascii"),
            "context": "w3plex.legacy-file",
        }
        for key in dict.fromkeys(keys)
    ]
    keys.clear()
    envelope, key = vault_format.seal(
        vault_format.canonical({"records": records}), entered.encode()
    )
    with LockedBuffer(key, protection=protection):
        unchanged()
        with CiphertextFile(backup) as destination:
            previous = destination.identity()
            if previous is not None:
                saved, previous = destination.read()
                if encrypted:
                    original = saved
                else:
                    parsed = file_format.parse(saved)
                    original = file_format.open_payload(
                        parsed, file_format.unwrap(parsed, entered.encode())
                    )
                if original != raw:
                    raise StoreChanged()
            elif encrypted:
                previous = destination.write(raw, expected=None)
            else:
                saved, backup_key = file_format.seal(raw, entered.encode())
                with LockedBuffer(backup_key, protection=protection):
                    previous = destination.write(saved.serialize(), expected=None)
            unchanged()
            if destination.identity() != previous:
                raise StoreChanged()
            storage.write(envelope.serialize(), expected=identity)
            check()
            if destination.identity() != previous:
                raise StoreChanged()
    vault = Vault(storage, protection=protection)
    try:
        vault.unlock(entered.encode())
        check()
        return vault
    except BaseException:
        vault.close()
        raise
