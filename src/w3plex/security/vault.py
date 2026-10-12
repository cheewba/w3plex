"""Service-owned encrypted vault. Do not expose this object as an agent tool.

Only SecretRef DTOs cross the public boundary. Plaintext methods are trusted
private host interfaces; a service authenticates their control connection.
"""

import base64
import json
import secrets
import threading
from collections.abc import Callable, Iterable
from typing import Any

from eth_account import Account as EthAccount

from .contracts import SecretKind, SecretRef, SecretUse
from .errors import AuthenticationFailed, InvalidStore, PermissionDenied, SecurityError
from .memory import LockedBuffer, ProcessProtection
from .storage import CiphertextFile, FileIdentity
from .vault_format import (
    DEFAULT_KDF,
    Envelope,
    KdfSettings,
    canonical,
    open_payload,
    parse,
    seal,
    unwrap,
    update_payload,
)

_USES = {
    SecretKind.WALLET: {
        SecretUse.TRANSACTION,
        SecretUse.MESSAGE,
        SecretUse.TYPED_MESSAGE,
    },
    SecretKind.SEED: {SecretUse.RECOVERY},
    SecretKind.PASSWORD: {SecretUse.RECOVERY},
    SecretKind.API: {SecretUse.HTTP},
    SecretKind.RPC: {SecretUse.HTTP},
    SecretKind.MODEL: {SecretUse.HTTP},
    SecretKind.LEGACY_FILE_KEY: {SecretUse.DECRYPT},
}


def _private[T](function: Callable[[], T]) -> T:
    """Raise fixed codes without the dependency exception or its cause chain.

    Exception frames still belong to the private host; never log their locals.
    """
    error = None
    try:
        return function()
    except SecurityError as exc:
        error = type(exc)
    except Exception:  # noqa: BLE001 -- private library errors are never forwarded
        error = SecurityError
    # Outside the exception handler: no __context__ chain with private locals.
    raise error()


def _new_record(
    kind: SecretKind, value: bytes, uses: Iterable[SecretUse]
) -> dict[str, Any]:
    allowed = set(uses)
    if (
        not isinstance(kind, SecretKind)
        or not isinstance(value, bytes)
        or not 1 <= len(value) <= 65536
        or not allowed
        or any(not isinstance(use, SecretUse) for use in allowed)
        or not allowed <= _USES[kind]
    ):
        raise InvalidStore()
    address = None
    if kind is SecretKind.LEGACY_FILE_KEY and len(value) != 32:
        raise InvalidStore()
    if kind is SecretKind.WALLET:
        if len(value) != 32:
            raise InvalidStore()
        address = _private(lambda: EthAccount.from_key(value).address)
    return {
        "id": secrets.token_hex(16),
        "kind": kind.value,
        "address": address,
        "uses": sorted(use.value for use in allowed),
        "value": base64.b64encode(value).decode("ascii"),
    }


def _parse_records(plaintext: bytes) -> list[dict[str, Any]]:
    valid = False
    records = []
    try:
        document = json.loads(plaintext)
        if (
            isinstance(document, dict)
            and set(document) == {"records"}
            and isinstance(document["records"], list)
            and len(document["records"]) <= 4096
        ):
            identifiers = set()
            for item in document["records"]:
                if not isinstance(item, dict) or set(item) != {
                    "id",
                    "kind",
                    "address",
                    "uses",
                    "value",
                }:
                    break
                identifier = item["id"]
                if (
                    not isinstance(identifier, str)
                    or len(identifier) != 32
                    or any(c not in "0123456789abcdef" for c in identifier)
                    or identifier in identifiers
                ):
                    break
                kind = SecretKind(item["kind"])
                if not isinstance(item["uses"], list) or not item["uses"]:
                    break
                uses = {SecretUse(use) for use in item["uses"]}
                if len(uses) != len(item["uses"]) or not uses <= _USES[kind]:
                    break
                value = base64.b64decode(item["value"], validate=True)
                if not 1 <= len(value) <= 65536:
                    break
                if kind is SecretKind.LEGACY_FILE_KEY and len(value) != 32:
                    break
                if kind is SecretKind.WALLET:
                    if (
                        len(value) != 32
                        or EthAccount.from_key(value).address != item["address"]
                    ):
                        break
                elif item["address"] is not None:
                    break
                identifiers.add(identifier)
                records.append(item)
            else:
                valid = True
    except (ValueError, TypeError, UnicodeError, RecursionError):
        pass
    if not valid:
        raise InvalidStore()
    return records


def _reference(record: dict[str, Any]) -> SecretRef:
    return SecretRef(record["id"], SecretKind(record["kind"]), record["address"])


class Vault:
    def __init__(self, storage: CiphertextFile, *, protection: ProcessProtection):
        self._storage = storage
        self._protection = protection
        self._mutex = threading.RLock()
        self._key: LockedBuffer | None = None
        self._envelope: Envelope | None = None
        self._identity: FileIdentity | None = None
        self._closed = False

    def __repr__(self):
        return "Vault(<private>)"

    def _check(self):
        self._protection.check()
        if self._closed:
            raise PermissionDenied()

    def _unlocked(self) -> tuple[Envelope, bytes]:
        self._check()
        if self._key is None or self._envelope is None:
            raise PermissionDenied()
        return self._envelope, self._key.copy_bytes()

    def create(self, password: bytes, *, settings: KdfSettings = DEFAULT_KDF):
        """Trusted private setup. Exclusive creation never overwrites any store."""

        def operation():
            with self._mutex:
                self._check()
                with LockedBuffer(bytes(32), protection=self._protection) as buffer:
                    envelope, key = seal(
                        canonical({"records": []}), password, settings=settings
                    )
                    buffer.replace(key)
                    self._storage.write(envelope.serialize(), expected=None)
                # Setup does not leave an implicitly unlocked session.
                self.lock()

        return _private(operation)

    def unlock(self, password: bytes):
        """Trusted private input; retain only a locked data-key allocation."""

        def operation():
            with self._mutex:
                self._check()
                self.lock()
                data, identity = self._storage.read()
                envelope = parse(data)
                buffer = LockedBuffer(bytes(32), protection=self._protection)
                try:
                    buffer.replace(unwrap(envelope, password))
                    _parse_records(open_payload(envelope, buffer.copy_bytes()))
                except BaseException:
                    buffer.close()
                    raise
                self._key, self._envelope, self._identity = buffer, envelope, identity

        return _private(operation)

    def lock(self):
        with self._mutex:
            buffer, self._key = self._key, None
            self._envelope = self._identity = None
            if buffer is not None:
                buffer.close()

    def _records(self) -> list[dict[str, Any]]:
        envelope, key = self._unlocked()
        # Unlock and writes validate this authenticated document. Parsing a use
        # must not decode unrelated wallet keys or derive their addresses again.
        return json.loads(open_payload(envelope, key))["records"]

    def references(self) -> tuple[SecretRef, ...]:
        return _private(lambda: tuple(_reference(record) for record in self._records()))

    def add(
        self, kind: SecretKind, value: bytes, *, uses: Iterable[SecretUse]
    ) -> SecretRef:
        return self.import_records([(kind, value, tuple(uses))])[0]

    def import_records(
        self, selected: Iterable[tuple[SecretKind, bytes, tuple[SecretUse, ...]]]
    ) -> tuple[SecretRef, ...]:
        """Trusted, already authorized private import; validate all then commit once.

        The host owns source approval and cancellation before this commit point.
        No source file is modified by this method.
        """

        def operation():
            with self._mutex:
                envelope, key = self._unlocked()
                records = self._records()
                additions = [
                    _new_record(kind, value, uses) for kind, value, uses in selected
                ]
                if not additions or len(records) + len(additions) > 4096:
                    raise InvalidStore()
                _parse_records(canonical({"records": records + additions}))
                updated = update_payload(
                    envelope, key, canonical({"records": records + additions})
                )
                try:
                    identity = self._storage.write(
                        updated.serialize(), expected=self._identity
                    )
                except BaseException:
                    self.lock()
                    raise
                self._envelope, self._identity = updated, identity
                return tuple(_reference(record) for record in additions)

        return _private(operation)

    def _use_secret[T](
        self, reference: SecretRef, use: SecretUse, consumer: Callable[[bytes], T]
    ) -> T:
        """Private service adapter only; requires its separate session/permit guard."""

        def operation():
            with self._mutex:
                for record in self._records():
                    if _reference(record) == reference and use.value in record["uses"]:
                        return consumer(
                            base64.b64decode(record["value"], validate=True)
                        )
                raise PermissionDenied()

        return _private(operation)

    def change_password(
        self,
        current_password: bytes,
        replacement: bytes,
        *,
        settings: KdfSettings = DEFAULT_KDF,
    ):
        def operation():
            with self._mutex:
                self._check()
                data, identity = self._storage.read()
                existing = parse(data)
                key = unwrap(existing, current_password)
                with LockedBuffer(key, protection=self._protection) as buffer:
                    plaintext = open_payload(existing, buffer.copy_bytes())
                    _parse_records(plaintext)
                    # Rotate the data key too; no old key is persisted.
                    replacement_envelope, replacement_key = seal(
                        plaintext,
                        replacement,
                        settings=settings,
                        store_id=existing.header["store_id"],
                    )
                    with LockedBuffer(replacement_key, protection=self._protection):
                        self._storage.write(
                            replacement_envelope.serialize(), expected=identity
                        )
                self.lock()

        try:
            return _private(operation)
        finally:
            self.lock()

    def backup(self, destination: CiphertextFile):
        def operation():
            with self._mutex:
                envelope, key = self._unlocked()
                _parse_records(open_payload(envelope, key))
                data, identity = self._storage.read()
                if identity != self._identity:
                    raise AuthenticationFailed()
                destination.write(data, expected=None)

        return _private(operation)

    def close(self):
        with self._mutex:
            self.lock()
            self._closed = True
            self._storage.close()
