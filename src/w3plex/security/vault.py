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

from .constants import (
    AES256_KEY_BYTES,
    IDENTIFIER_BYTES,
    IDENTIFIER_HEX_LENGTH,
    MAX_RECORD_BYTES,
)
from .diagnostics import (
    private_call as private_call,  # noqa: PLC0414 -- retain the existing host import
    safe_error_type,
)
from .errors import AuthenticationFailed, InvalidStore, PermissionDenied, SecurityError
from .memory import LockedBuffer, ProcessProtection
from .storage import CiphertextFile, FileIdentity, StoreChanged
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

# Bound the number of records and the work performed by batch operations.
_MAX_RECORD_COUNT = 4096


class Vault:
    """Store encrypted records and keep their data key only while unlocked."""

    def __init__(self, storage: CiphertextFile, *, protection: ProcessProtection):
        """Use file storage and process protection for a new vault object.

        Args:
            storage: Encrypted file storage. The vault closes it in close().
            protection: Process protection used by the vault and its key buffers.

        Returns:
            None.
        """
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
        """Return the path of the vault file.

        Returns:
            The storage path as a Path object.
        """
        return self._storage.path

    def bind_lock(self, callback: Callable[[], None] | None) -> None:
        """Set the main host callback for lock notifications.

        A second live main callback is not allowed. Use add_lock_listener() for other
        listeners.

        Args:
            callback: A bound method called when the vault locks. None removes the main
                callback.

        Returns:
            None.
        """
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
        """Add another callback without replacing the main host callback.

        Args:
            callback: A bound method to call when the vault locks.

        Returns:
            None.
        """
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
        """Check whether this vault has a live data key.

        Returns:
            True if the vault is open and unlocked.
        """
        with self._mutex:
            return (
                not self._closed
                and self._key is not None
                and self._envelope is not None
            )

    def check(self):
        """Check that process protection is active and the vault is open.

        Returns:
            None.
        """
        self._protection.check()
        if self._closed:
            raise PermissionDenied()

    def _unlocked(self) -> tuple[Envelope, bytes]:
        self.check()
        if self._key is None or self._envelope is None:
            raise PermissionDenied()
        return self._envelope, self._key.copy_bytes()

    def create(self, password: bytes, *, settings: KdfSettings = DEFAULT_KDF):
        """Create an empty vault without replacing an existing file.

        The vault stays locked after setup.

        Args:
            password: Master password bytes for the new vault.
            settings: Argon2id settings that control the time and memory used to derive
                a key.

        Returns:
            None.
        """

        def operation():
            with self._mutex:
                self.check()
                with LockedBuffer(
                    bytes(AES256_KEY_BYTES), protection=self._protection
                ) as buffer:
                    envelope, key = seal(
                        canonical({"records": []}), password, settings=settings
                    )
                    buffer.replace(key)
                    self._storage.write(envelope.serialize(), expected=None)
                # Setup does not leave an implicitly unlocked session.
                self.lock()

        return private_call(operation)

    def unlock(self, password: bytes):
        """Unlock the vault using its master password.

        The vault keeps its data key in locked memory. It does not keep the password.

        Args:
            password: Master password bytes for the existing vault.

        Returns:
            None.
        """

        def operation():
            with self._mutex:
                self.check()
                self.lock()

                data, identity = self._storage.read()
                envelope = parse(data)

                buffer = LockedBuffer(
                    bytes(AES256_KEY_BYTES), protection=self._protection
                )
                try:
                    buffer.replace(unwrap(envelope, password))
                    self.validate_records(open_payload(envelope, buffer.copy_bytes()))
                except BaseException:
                    buffer.close()
                    raise

                self._key, self._envelope, self._identity = buffer, envelope, identity

        return private_call(operation)

    def reload(self) -> None:
        """Load file changes using the current data key.

        The file must use the same store ID and password wrapper. Values of records that
        remain in the file cannot change. Success keeps the session number. Any failure
        locks the vault. This does not detect an older valid copy of the file.

        Returns:
            None.
        """

        def operation():
            with self._mutex:
                try:
                    previous, key = self._unlocked()
                    generation = self._generation
                    data, identity = self._storage.read()
                    envelope = parse(data)
                    if envelope.wrapped_key != previous.wrapped_key or {
                        name: value
                        for name, value in envelope.header.items()
                        if name != "data_nonce"
                    } != {
                        name: value
                        for name, value in previous.header.items()
                        if name != "data_nonce"
                    }:
                        raise AuthenticationFailed()
                    # Reload can add or remove records, but cannot change existing values.
                    records = self.validate_records(open_payload(envelope, key))
                    existing = {record["id"]: record for record in self._records()}
                    if any(
                        record["id"] in existing
                        and canonical(record) != canonical(existing[record["id"]])
                        for record in records
                    ):
                        raise AuthenticationFailed()
                    if self.checkpoint() != generation:
                        raise PermissionDenied()
                    self._envelope, self._identity = envelope, identity
                except BaseException:
                    self.lock()
                    raise

        return private_call(operation)

    def lock(self):
        """Remove the session key and notify all listeners.

        All listeners are called even if a cleanup step fails. The error is reported
        after cleanup.

        Returns:
            None.
        """
        failure: type[SecurityError] | None = None
        interruption: BaseException | None = None
        with self._mutex:
            # Mark the session as locked before calling cleanup callbacks.
            self._generation += 1
            buffer, self._key = self._key, None
            self._envelope = self._identity = None

            try:
                if buffer is not None:
                    buffer.close()
            except SecurityError as exc:
                failure = safe_error_type(exc)
            except Exception:  # noqa: BLE001 -- still notify data owners
                failure = SecurityError
            except BaseException as exc:  # noqa: BLE001 -- finish cleanup before cancellation
                interruption = exc
            # A failing listener must not prevent other owners from clearing caches.
            references = (
                [] if self._lock_listener is None else [self._lock_listener]
            ) + self._lock_observers
            for reference in references:
                listener = reference()
                if listener is not None:
                    try:
                        listener()
                    except SecurityError as exc:
                        failure = safe_error_type(exc)
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
        """Return the shared lock for operations that need several vault calls.

        Returns:
            The vault's reentrant thread lock.
        """
        return self._mutex

    @property
    def protection(self) -> ProcessProtection:
        """Return the process protection used by this vault.

        Returns:
            The ProcessProtection object shared with the key buffers.
        """
        return self._protection

    def checkpoint(self) -> int:
        """Return the current unlocked session number.

        Returns:
            A number that changes when the vault is locked or unlocked. Compare it later
            to detect a session change.
        """
        with self._mutex:
            self.check()
            if not self.is_unlocked:
                raise PermissionDenied()
            return self._generation

    def validate_records(self, plaintext: bytes) -> list[dict[str, Any]]:
        """Check a decrypted record document before using it.

        Args:
            plaintext: UTF-8 JSON bytes from a checked and decrypted vault payload.

        Returns:
            The list of validated record dictionaries.
        """
        document = json.loads(
            plaintext,
            object_pairs_hook=unique_fields,
            parse_constant=reject_json_constant,
        )
        if (
            not isinstance(document, dict)
            or set(document) != {"records"}
            or not isinstance(document["records"], list)
            or len(document["records"]) > _MAX_RECORD_COUNT
        ):
            raise InvalidStore()
        seen = set()
        for record in document["records"]:
            if not isinstance(record, dict) or not {"id", "value"} <= record.keys():
                raise InvalidStore()
            identifier = record["id"]
            if (
                type(identifier) is not str
                or len(identifier) != IDENTIFIER_HEX_LENGTH
                or any(c not in "0123456789abcdef" for c in identifier)
                or identifier in seen
            ):
                raise InvalidStore()
            if type(record["value"]) is not str:
                raise InvalidStore()
            value = base64.b64decode(record["value"], validate=True)
            if len(value) > MAX_RECORD_BYTES:
                raise InvalidStore()
            seen.add(identifier)
        return document["records"]

    def identifiers(self) -> tuple[str, ...]:
        """List record IDs from the current unlocked data.

        Returns:
            A tuple of IDs in stored record order.
        """

        def operation():
            with self._mutex:
                return tuple(record["id"] for record in self._records())

        return private_call(operation)

    def metadata(self, identifier: str) -> dict[str, Any]:
        """Read a record's metadata without returning its stored value.

        Args:
            identifier: ID of the record to read.

        Returns:
            A metadata dictionary without the id and value fields.
        """

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
        """Find records by metadata without decrypting once per field.

        Args:
            criteria: Metadata field/value pairs to match. The id and value fields
                cannot be used.

        Returns:
            Matching record IDs in stored record order.
        """

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
        """Save one value and its optional metadata.

        Args:
            value: Bytes to save as a record that cannot change later.
            metadata: Optional record details. The id and value fields are managed by
                the vault.

        Returns:
            The new record ID.
        """
        return self.import_entries([(value, metadata or {})])[0]

    def import_entries(
        self, selected: Iterable[tuple[bytes, dict[str, Any]]]
    ) -> tuple[str, ...]:
        """Save several values in one file update.

        Args:
            selected: Pairs of value bytes and metadata dictionaries. Each value can
                contain up to 1 MiB.

        Returns:
            New record IDs in the same order as the input values.
        """

        def operation():
            with self._mutex:
                envelope, key = self._unlocked()
                records = self._records()
                additions = []
                for value, metadata in selected:
                    if (
                        type(value) is not bytes
                        or len(value) > MAX_RECORD_BYTES
                        or type(metadata) is not dict
                        or {"id", "value"} & metadata.keys()
                    ):
                        raise InvalidStore()
                    additions.append(
                        {
                            **metadata,
                            "id": secrets.token_hex(IDENTIFIER_BYTES),
                            "value": base64.b64encode(value).decode("ascii"),
                        }
                    )
                if not additions or len(records) + len(additions) > _MAX_RECORD_COUNT:
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

    def delete_entries(self, selected: Iterable[str]) -> tuple[str, ...]:
        """Remove selected records in one file update.

        An empty selection still checks whether the stored file has changed. A failed
        write locks the vault; read the file again before retrying.

        Args:
            selected: Up to 4096 record IDs to remove. Duplicate and missing IDs are
                ignored.

        Returns:
            Removed IDs in their original record order.
        """

        def operation():
            if isinstance(selected, (str, bytes)) or not isinstance(selected, Iterable):
                raise InvalidStore()
            identifiers = set()
            for index, identifier in enumerate(selected):
                if (
                    index >= _MAX_RECORD_COUNT
                    or type(identifier) is not str
                    or len(identifier) != IDENTIFIER_HEX_LENGTH
                    or any(c not in "0123456789abcdef" for c in identifier)
                ):
                    raise InvalidStore()
                identifiers.add(identifier)
            with self._mutex:
                envelope, key = self._unlocked()
                records = self._records()
                removed = tuple(
                    record["id"] for record in records if record["id"] in identifiers
                )
                survivors = [
                    record for record in records if record["id"] not in identifiers
                ]
                plaintext = canonical({"records": survivors})
                self.validate_records(plaintext)
                try:
                    if not removed:
                        with self._storage.writer_guard():
                            if self._storage.read()[1] != self._identity:
                                raise StoreChanged()
                        return ()
                    updated = update_payload(envelope, key, plaintext)
                    identity = self._storage.write(
                        updated.serialize(), expected=self._identity
                    )
                except BaseException:
                    self.lock()
                    raise
                self._envelope, self._identity = updated, identity
                return removed

        return private_call(operation)

    def read(self, identifier: str) -> bytes:
        """Read a record from the current unlocked data.

        Args:
            identifier: ID of the record to read.

        Returns:
            The stored bytes.
        """

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
        """Set a new password and data key.

        The vault is locked after the call, even if it fails.

        Args:
            current_password: Current master password bytes.
            replacement: New master password bytes.
            settings: Argon2id settings that control the time and memory used to derive
                a key.

        Returns:
            None.
        """

        def operation():
            self.check()
            data, identity = self._storage.read()
            existing = parse(data)
            with (
                LockedBuffer(
                    bytes(AES256_KEY_BYTES), protection=self._protection
                ) as buffer,
                LockedBuffer(
                    bytes(AES256_KEY_BYTES), protection=self._protection
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
                self._storage.write(replacement_envelope.serialize(), expected=identity)

        # Lock the vault before another thread can use the updated file.
        with self._mutex:
            try:
                return private_call(operation)
            finally:
                self.lock()

    def backup(self, destination: CiphertextFile):
        """Copy the current encrypted file without replacing an existing backup.

        Args:
            destination: CiphertextFile for a new backup path. The caller must close it.

        Returns:
            None.
        """

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
        """Lock the vault and close its file storage.

        Storage is closed even if a lock listener fails.

        Returns:
            None.
        """
        with self._mutex:
            try:
                self.lock()
            finally:
                self._closed = True
                self._storage.close()
