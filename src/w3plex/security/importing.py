"""Private, non-destructive import into the new vault.

KS01 stores ENC1 file decryption keys, not EVM wallet keys. Keep that type
distinct. Only explicit key-line input produces wallet records.
"""

import asyncio
import base64
import hashlib
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from .contracts import SecretKind, SecretRef, SecretUse
from .diagnostics import private_async
from .errors import AuthenticationFailed, InvalidStore, PermissionDenied
from .interaction import FieldKind, InputField, PrivateInput
from .legacy import LegacyContext
from .session import Session
from .snapshots import snapshot_file
from .vault import Vault, new_record


class LegacyImporter:
    """Trusted control interface. Source selection is never an agent tool input."""

    def __init__(self, vault: Vault, session: Session, *, private_input: PrivateInput):
        self._vault, self._session, self._input = vault, session, private_input

    async def _confirm(self, operation: str, step: str, prompt: str) -> bool:
        reply = await self._input.ask(
            operation, step, (InputField("confirm", FieldKind.CONFIRM, prompt),)
        )
        return reply.values.get("confirm") is True

    async def _keystore(
        self, raw: bytes, *, operation: str, generation: str
    ) -> list[bytes]:
        if not 16 <= len(raw) <= 1024 * 1024:
            raise InvalidStore()
        salt, payload = raw[:16], raw[16:]
        if not payload.startswith(b"KS01"):
            keys = self._session.use(
                generation, operation, lambda: LegacyContext._parse_keys(payload)
            )
            if not keys:
                raise InvalidStore()
            return keys
        for attempt in range(3):
            reply = await self._input.ask(
                operation,
                f"legacy-master-{attempt}",
                (
                    InputField(
                        "password",
                        FieldKind.SECRET,
                        "Unlock the selected legacy keystore",
                    ),
                ),
            )
            entered = reply.values.get("password")
            if not isinstance(entered, str):
                raise PermissionDenied()
            password = entered.encode()

            def decode(password: bytes = password):
                for n in (32768, 16384, 8192, 4096):
                    key = hashlib.scrypt(
                        password,
                        salt=salt,
                        n=n,
                        r=8,
                        p=1,
                        dklen=32,
                        maxmem=128 * 1024 * 1024,
                    )
                    try:
                        plaintext = Fernet(base64.urlsafe_b64encode(key)).decrypt(
                            payload[4:]
                        )
                    except InvalidToken:
                        continue
                    keys = LegacyContext._parse_keys(plaintext)
                    if not keys:
                        raise InvalidStore()
                    return keys
                return None

            keys = self._session.use(generation, operation, decode)
            if keys is not None:
                return keys
        raise AuthenticationFailed()

    @private_async
    async def import_source(
        self,
        source: Path,
        *,
        operation: str,
        kind: SecretKind,
        legacy_keystore: Path | None = None,
        expected_addresses: tuple[str, ...] | None = None,
    ) -> tuple[SecretRef, ...]:
        if not isinstance(kind, SecretKind) or (
            expected_addresses is not None and kind is not SecretKind.WALLET
        ):
            raise PermissionDenied()
        normalized = Path(source.absolute())
        snapshot = snapshot_file(normalized)
        if not await self._confirm(
            operation,
            "legacy-source",
            f"Import {normalized}; SHA-256 {hashlib.sha256(snapshot.raw).hexdigest()}",
        ):
            raise PermissionDenied()
        keystore = None
        keystore_snapshot = None
        if legacy_keystore is not None:
            if kind is SecretKind.LEGACY_FILE_KEY:
                raise PermissionDenied()
            keystore = Path(legacy_keystore.absolute())
            keystore_snapshot = snapshot_file(keystore)
            if not await self._confirm(
                operation,
                "legacy-keystore",
                f"Use {keystore}; SHA-256 {hashlib.sha256(keystore_snapshot.raw).hexdigest()}",
            ):
                raise PermissionDenied()
        status = await self._session.unlock(operation)
        self._session.check(status.generation)
        task = asyncio.current_task()
        if task is None:
            raise PermissionDenied()
        self._session.track(status.generation, task)
        if snapshot_file(normalized) != snapshot or (
            keystore is not None and snapshot_file(keystore) != keystore_snapshot
        ):
            raise PermissionDenied()
        addresses: tuple[str, ...] = ()
        if kind is SecretKind.LEGACY_FILE_KEY:
            values = await self._keystore(
                snapshot.raw, operation=operation, generation=status.generation
            )
            selected = [(kind, value, (SecretUse.DECRYPT,)) for value in values]
        else:
            context = LegacyContext(None)
            try:
                if keystore_snapshot is not None:
                    context._keys = await self._keystore(
                        keystore_snapshot.raw,
                        operation=operation,
                        generation=status.generation,
                    )
                plaintext = await context.decrypt_private(
                    snapshot.raw,
                    source=normalized,
                    private_input=self._input,
                    operation=operation,
                    session=self._session,
                    generation=status.generation,
                )
                if kind is SecretKind.WALLET:
                    selected = []
                    text = plaintext.decode("utf-8")
                    for line in text.splitlines():
                        value = line.strip()
                        if not value or value.startswith("#"):
                            continue
                        key = bytes.fromhex(value.removeprefix("0x"))
                        selected.append(
                            (
                                kind,
                                key,
                                (
                                    SecretUse.TRANSACTION,
                                    SecretUse.MESSAGE,
                                    SecretUse.TYPED_MESSAGE,
                                ),
                            )
                        )
                    if not selected:
                        raise InvalidStore()
                    addresses = tuple(
                        new_record(record_kind, value, uses)["address"]
                        for record_kind, value, uses in selected
                    )
                    if expected_addresses is not None and tuple(
                        address.lower() for address in addresses
                    ) != tuple(address.lower() for address in expected_addresses):
                        raise InvalidStore()
                elif kind in {SecretKind.API, SecretKind.RPC, SecretKind.MODEL}:
                    selected = [(kind, plaintext.strip(), (SecretUse.HTTP,))]
                elif kind in {SecretKind.SEED, SecretKind.PASSWORD}:
                    selected = [(kind, plaintext, (SecretUse.RECOVERY,))]
                else:
                    raise InvalidStore()
            finally:
                context.lock()
        # Validate every record before final consent or any destination write.
        for record_kind, value, uses in selected:
            new_record(record_kind, value, uses)
        summary = f"Save {len(selected)} validated {kind.value} record(s)"
        if kind is SecretKind.WALLET:
            summary += ": " + ", ".join(addresses)
        if not await self._confirm(
            operation,
            "legacy-commit",
            summary,
        ):
            raise PermissionDenied()
        if snapshot_file(normalized) != snapshot or (
            keystore is not None and snapshot_file(keystore) != keystore_snapshot
        ):
            raise PermissionDenied()
        return self._session.use(
            status.generation, operation, lambda: self._vault.import_records(selected)
        )
