"""Encrypted data storage with opaque metadata and explicit lock/unlock.

This module has no wallet types, application permissions or agent interfaces.
"""

import base64
import json
import secrets
import threading
import weakref
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

from .diagnostics import safe_error_type
from .errors import AuthenticationFailed, InvalidStore, PermissionDenied, SecurityError
from .memory import LockedBuffer, ProcessProtection
from .storage import CiphertextFile, FileIdentity, UnsafeStorage
from .vault_format import (
    DEFAULT_KDF,
    Envelope,
    KdfSettings,
    canonical,
    open_payload,
    parse,
    reject_json_constant,
    seal,
    unique_fields,
    unwrap,
    update_payload,
)


def private_call[T](function: Callable[[], T]) -> T:
    """Raise fixed codes without the dependency exception or its cause chain.

    Exception frames still belong to the private host; never log their locals.
    """
    error = None
    try:
        return function()
    except SecurityError as exc:
        error = safe_error_type(exc)
    except Exception:  # noqa: BLE001 -- private library errors are never forwarded
        error = SecurityError
    del function
    # Outside the exception handler: no __context__ chain with private locals.
    raise error()


class Vault:
    def __init__(self, storage: CiphertextFile, *, protection: ProcessProtection):
        if not storage.private:
            raise UnsafeStorage()
        self._storage = storage
        self._protection = protection
        self._mutex = threading.RLock()
        self._key: LockedBuffer | None = None
        self._envelope: Envelope | None = None
        self._identity: FileIdentity | None = None
        self._closed = False
        self._generation = 0
        self._lock_listener: weakref.WeakMethod | None = None
        self._lock_observers: list[weakref.WeakMethod] = []

    def __repr__(self):
        return "Vault(<private>)"

    @property
    def path(self) -> Path:
        """Trusted storage location for private input; never a public RPC field."""
        return self._storage.path

    def bind_lock(self, callback: Callable[[], None] | None) -> None:
        """One host session owns lock notification; standalone vaults need none."""
        with self._mutex:
            if (
                callback is not None
                and self._lock_listener is not None
                and self._lock_listener() is not None
            ):
                raise PermissionDenied()
            self._lock_listener = (
                None if callback is None else weakref.WeakMethod(callback)
            )

    def add_lock_listener(self, callback: Callable[[], None]) -> None:
        """Notify borrowed data owners without replacing the primary host owner."""
        with self._mutex:
            self._lock_observers = [
                reference
                for reference in self._lock_observers
                if reference() is not None
            ]
            reference = weakref.WeakMethod(callback)
            if reference not in self._lock_observers:
                self._lock_observers.append(reference)

    @property
    def is_unlocked(self) -> bool:
        """Host-only state check; never returns unlock material."""
        with self._mutex:
            return (
                not self._closed
                and self._key is not None
                and self._envelope is not None
            )

    def check(self):
        self._protection.check()
        if self._closed:
            raise PermissionDenied()

    def _unlocked(self) -> tuple[Envelope, bytes]:
        self.check()
        if self._key is None or self._envelope is None:
            raise PermissionDenied()
        return self._envelope, self._key.copy_bytes()

    def create(self, password: bytes, *, settings: KdfSettings = DEFAULT_KDF):
        """Trusted private setup. Exclusive creation never overwrites any store."""

        def operation():
            with self._mutex:
                self.check()
                with LockedBuffer(bytes(32), protection=self._protection) as buffer:
                    envelope, key = seal(
                        canonical({"records": []}), password, settings=settings
                    )
                    buffer.replace(key)
                    self._storage.write(envelope.serialize(), expected=None)
                # Setup does not leave an implicitly unlocked session.
                self.lock()

        return private_call(operation)

    def unlock(self, password: bytes):
        """Trusted private input; retain only a locked data-key allocation."""

        def operation():
            with self._mutex:
                self.check()
                self.lock()
                data, identity = self._storage.read()
                envelope = parse(data)
                buffer = LockedBuffer(bytes(32), protection=self._protection)
                try:
                    buffer.replace(unwrap(envelope, password))
                    self.validate_records(open_payload(envelope, buffer.copy_bytes()))
                except BaseException:
                    buffer.close()
                    raise
                self._key, self._envelope, self._identity = buffer, envelope, identity

        return private_call(operation)

    def lock(self):
        failure: type[SecurityError] | None = None
        interruption: BaseException | None = None
        with self._mutex:
            self._generation += 1
            buffer, self._key = self._key, None
            self._envelope = self._identity = None
            try:
                if buffer is not None:
                    buffer.close()
            except SecurityError as exc:
                failure = type(exc)
            except Exception:  # noqa: BLE001 -- still notify data owners
                failure = SecurityError
            except BaseException as exc:  # noqa: BLE001 -- finish cleanup before cancellation
                interruption = exc
            references = (
                [] if self._lock_listener is None else [self._lock_listener]
            ) + self._lock_observers
            for reference in references:
                listener = reference()
                if listener is not None:
                    try:
                        listener()
                    except SecurityError as exc:
                        failure = type(exc)
                    except Exception:  # noqa: BLE001 -- notify every data owner
                        failure = SecurityError
                    except BaseException as exc:  # noqa: BLE001 -- finish notifying every data owner
                        interruption = exc
        if interruption is not None:
            raise interruption
        if failure is not None:
            raise failure()

    def _records(self) -> list[dict[str, Any]]:
        envelope, key = self._unlocked()
        # Unlock and writes validate this authenticated document.
        return json.loads(open_payload(envelope, key))["records"]

    @property
    def mutex(self):
        return self._mutex

    @property
    def protection(self) -> ProcessProtection:
        return self._protection

    def checkpoint(self) -> int:
        with self._mutex:
            self.check()
            if not self.is_unlocked:
                raise PermissionDenied()
            return self._generation

    def validate_records(self, plaintext: bytes) -> list[dict[str, Any]]:
        document = json.loads(
            plaintext,
            object_pairs_hook=unique_fields,
            parse_constant=reject_json_constant,
        )
        if (
            not isinstance(document, dict)
            or set(document) != {"records"}
            or not isinstance(document["records"], list)
            or len(document["records"]) > 4096
        ):
            raise InvalidStore()
        seen = set()
        for record in document["records"]:
            if not isinstance(record, dict) or not {"id", "value"} <= record.keys():
                raise InvalidStore()
            identifier = record["id"]
            if (
                type(identifier) is not str
                or len(identifier) != 32
                or any(c not in "0123456789abcdef" for c in identifier)
                or identifier in seen
            ):
                raise InvalidStore()
            if type(record["value"]) is not str:
                raise InvalidStore()
            value = base64.b64decode(record["value"], validate=True)
            if len(value) > 1024 * 1024:
                raise InvalidStore()
            seen.add(identifier)
        return document["records"]

    def identifiers(self) -> tuple[str, ...]:
        def operation():
            with self._mutex:
                return tuple(record["id"] for record in self._records())

        return private_call(operation)

    def metadata(self, identifier: str) -> dict[str, Any]:
        def operation():
            with self._mutex:
                for record in self._records():
                    if record["id"] == identifier:
                        return {
                            key: value
                            for key, value in record.items()
                            if key not in {"id", "value"}
                        }
                raise PermissionDenied()

        return private_call(operation)

    def find_metadata(self, criteria: dict[str, str]) -> tuple[str, ...]:
        """Find opaque metadata without repeatedly decrypting the entire store."""

        def operation():
            if (
                type(criteria) is not dict
                or not criteria
                or any(
                    type(name) is not str
                    or name in {"id", "value"}
                    or type(value) is not str
                    for name, value in criteria.items()
                )
            ):
                raise InvalidStore()
            with self._mutex:
                return tuple(
                    record["id"]
                    for record in self._records()
                    if all(
                        record.get(name) == value for name, value in criteria.items()
                    )
                )

        return private_call(operation)

    def save(self, value: bytes, *, metadata: dict[str, Any] | None = None) -> str:
        return self.import_entries([(value, metadata or {})])[0]

    def import_entries(
        self, selected: Iterable[tuple[bytes, dict[str, Any]]]
    ) -> tuple[str, ...]:
        """Validate generic values and opaque metadata, then commit once."""

        def operation():
            with self._mutex:
                envelope, key = self._unlocked()
                records = self._records()
                additions = []
                for value, metadata in selected:
                    if (
                        type(value) is not bytes
                        or len(value) > 1024 * 1024
                        or type(metadata) is not dict
                        or {"id", "value"} & metadata.keys()
                    ):
                        raise InvalidStore()
                    additions.append(
                        {
                            **metadata,
                            "id": secrets.token_hex(16),
                            "value": base64.b64encode(value).decode("ascii"),
                        }
                    )
                if not additions or len(records) + len(additions) > 4096:
                    raise InvalidStore()
                plaintext = canonical({"records": records + additions})
                self.validate_records(plaintext)
                updated = update_payload(envelope, key, plaintext)
                try:
                    identity = self._storage.write(
                        updated.serialize(), expected=self._identity
                    )
                except BaseException:
                    self.lock()
                    raise
                self._envelope, self._identity = updated, identity
                return tuple(record["id"] for record in additions)

        return private_call(operation)

    def read(self, identifier: str) -> bytes:
        def operation():
            with self._mutex:
                for record in self._records():
                    if record["id"] == identifier:
                        return base64.b64decode(record["value"], validate=True)
                raise PermissionDenied()

        return private_call(operation)

    def change_password(
        self,
        current_password: bytes,
        replacement: bytes,
        *,
        settings: KdfSettings = DEFAULT_KDF,
    ):
        def operation():
            with self._mutex:
                self.check()
                data, identity = self._storage.read()
                existing = parse(data)
                with (
                    LockedBuffer(bytes(32), protection=self._protection) as buffer,
                    LockedBuffer(
                        bytes(32), protection=self._protection
                    ) as replacement_buffer,
                ):
                    buffer.replace(unwrap(existing, current_password))
                    plaintext = open_payload(existing, buffer.copy_bytes())
                    self.validate_records(plaintext)
                    # Rotate the data key too; no old key is persisted.
                    replacement_envelope, replacement_key = seal(
                        plaintext,
                        replacement,
                        settings=settings,
                        store_id=existing.header["store_id"],
                    )
                    replacement_buffer.replace(replacement_key)
                    self._storage.write(
                        replacement_envelope.serialize(), expected=identity
                    )
                self.lock()

        try:
            return private_call(operation)
        finally:
            self.lock()

    def backup(self, destination: CiphertextFile):
        def operation():
            with self._mutex:
                self.check()
                if self._key is None or self._envelope is None:
                    raise PermissionDenied()
                data, identity = self._storage.read()
                if identity != self._identity:
                    raise AuthenticationFailed()
                destination.write(data, expected=None)

        return private_call(operation)

    def close(self):
        with self._mutex:
            self.lock()
            self._closed = True
            self._storage.close()
