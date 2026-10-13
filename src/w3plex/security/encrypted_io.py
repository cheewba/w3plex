"""Shared transparent reads of ordinary, ENC1 and W3FILE1 inputs."""

import hashlib
import io
import os
import threading
from collections.abc import Callable
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import file_format
from .errors import (
    AuthenticationFailed,
    InteractionRequired,
    InvalidStore,
    PermissionDenied,
    SecurityError,
)
from .io_activation import activate, deactivate, is_active
from .legacy import LegacyContext, LegacyPasswordRequest
from .memory import LockedBuffer, ProcessProtection
from .vault import Vault, private_call

_MAXIMUM_KEYS = 1024


@dataclass(frozen=True, repr=False)
class PasswordRequest:
    kind: str
    source: Path

    def __repr__(self) -> str:
        return "PasswordRequest(<private>)"


def detect_format(prefix: bytes) -> str:
    """Recognized unsupported containers must never become plaintext reads."""
    if prefix.startswith(b"ENC1"):
        return "legacy"
    if prefix.startswith(file_format.MAGIC):
        return "modern"
    if prefix.startswith((b"W3FILE", b"W3VAULT", b"KS01")):
        raise InvalidStore()
    return "plain"


class EncryptedIOContext:
    _w3plex_security_context = True

    def __init__(
        self,
        *,
        protection: ProcessProtection,
        input_handler: Callable[[PasswordRequest], str] | None = None,
        legacy_keystore_path: str | Path | None = None,
        persist_legacy_keys: bool = False,
        keystore: Vault | None = None,
        persist_keys: bool = False,
        opener: Callable[..., Any] = io.open,
    ):
        if type(persist_keys) is not bool or (persist_keys and keystore is None):
            raise InvalidStore()
        self._protection = protection
        self._keystore = keystore
        self._persist_keys = persist_keys
        self._input = input_handler
        self._opener = opener
        self._legacy = LegacyContext(
            legacy_keystore_path,
            input_handler=self._legacy_password,
            persist_keys=persist_legacy_keys,
            opener=opener,
        )
        self._keys: dict[str, LockedBuffer] = {}
        self._mutex = threading.RLock()
        self._key_mutex = threading.RLock()
        self._generation = 0
        self._closed = False
        if keystore is not None:
            keystore.add_lock_listener(self._clear_keys)

    def __repr__(self) -> str:
        return "EncryptedIOContext(<private>)"

    @property
    def generation(self) -> int:
        with self._mutex:
            return self._generation

    @property
    def active(self) -> bool:
        return is_active(self)

    def _check(self, generation: int) -> None:
        if self._closed or generation != self._generation:
            raise PermissionDenied()

    def _password(self, kind: str, source: str | Path) -> str:
        if self._input is None:
            raise InteractionRequired()
        handler = self._input
        value = private_call(lambda: handler(PasswordRequest(kind, Path(source))))
        if type(value) is not str:
            raise InteractionRequired()
        return value

    def _legacy_password(self, request: LegacyPasswordRequest) -> str:
        return self._password(request.kind, request.source)

    def unlock_keystore(self) -> None:
        generation = self.generation
        self._protection.check()
        keystore = self._keystore
        if keystore is None:
            raise InteractionRequired()
        if keystore.is_unlocked:
            with self._mutex:
                self._check(generation)
            return
        password = self._password("master", keystore.path)
        with self._mutex:
            self._check(generation)
        create = not keystore.path.exists()
        if create and self._password("master_confirm", keystore.path) != password:
            raise AuthenticationFailed()
        with self._mutex:
            self._check(generation)
            if create:
                keystore.create(password.encode("utf-8"))
            keystore.unlock(password.encode("utf-8"))

    def _stored_key(self, fingerprint: str) -> bytes | None:
        if self._keystore is None:
            return None
        identifiers = self._keystore.find_metadata(
            {"context": "w3plex.file", "fingerprint": fingerprint}
        )
        if not identifiers:
            return None
        if len(identifiers) != 1:
            raise InvalidStore()
        key = self._keystore.read(identifiers[0])
        if len(key) != 32:
            raise InvalidStore()
        return key

    def _remember_key(self, fingerprint: str, key: bytes) -> None:
        keystore = self._keystore
        if keystore is None:
            raise InteractionRequired()
        with keystore.mutex:
            previous = self._stored_key(fingerprint)
            if previous is None:
                keystore.save(
                    key, metadata={"context": "w3plex.file", "fingerprint": fingerprint}
                )
            elif previous != key:
                raise InvalidStore()

    def _check_keystore(self, generation: int | None) -> None:
        if self._keystore is not None and self._keystore.checkpoint() != generation:
            raise PermissionDenied()

    def decrypt_bytes(
        self, raw: bytes, *, source: str | Path, password: str | None = None
    ) -> bytes:
        generation = self.generation
        kind = detect_format(raw)
        with self._mutex:
            self._check(generation)
        if kind == "plain":
            return raw
        if kind == "legacy":
            value = self._legacy.decrypt_bytes(raw, source=source, password=password)
            with self._mutex:
                self._check(generation)
            return value
        envelope = file_format.parse(raw)
        self._protection.check()
        if self._keystore is not None:
            self.unlock_keystore()
        store_generation = (
            None if self._keystore is None else self._keystore.checkpoint()
        )
        fingerprint = hashlib.sha256(raw).hexdigest()
        with self._mutex:
            self._check(generation)
            with self._key_mutex:
                buffer = self._keys.get(fingerprint) if password is None else None
                key = None if buffer is None else buffer.copy_bytes()
            if key is None and password is None:
                key = self._stored_key(fingerprint)
            with self._key_mutex:
                if key is None and len(self._keys) >= _MAXIMUM_KEYS:
                    raise InvalidStore()
        if key is None:
            secret = self._password("file", source) if password is None else password
            with self._mutex:
                self._check(generation)
                self._check_keystore(store_generation)
            key = file_format.unwrap(envelope, secret.encode("utf-8"))
        value = file_format.open_payload(envelope, key)
        with (
            self._mutex,
            nullcontext() if self._keystore is None else self._keystore.mutex,
        ):
            self._check(generation)
            self._check_keystore(store_generation)
            self._protection.check()
            if self._persist_keys:
                self._remember_key(fingerprint, key)
            else:
                with self._key_mutex:
                    if fingerprint not in self._keys:
                        if len(self._keys) >= _MAXIMUM_KEYS:
                            raise InvalidStore()
                        self._keys[fingerprint] = LockedBuffer(
                            key, protection=self._protection
                        )
        return value

    def open(
        self,
        file,
        mode="r",
        buffering=-1,
        encoding=None,
        errors=None,
        newline=None,
        closefd=True,
        opener=None,
    ):
        args = (file, mode, buffering, encoding, errors, newline, closefd, opener)
        handle = self._opener(*args)
        if (
            set(mode) - {"r", "b", "t"}
            or isinstance(file, int)
            or not handle.seekable()
        ):
            return handle
        try:
            binary = "b" in mode
            stream = handle if binary else handle.buffer
            kind = detect_format(stream.read(16))
            handle.seek(0)
            if kind == "plain":
                return handle
            raw = stream.read(file_format.MAXIMUM_SIZE + 1)
            if len(raw) > file_format.MAXIMUM_SIZE:
                raise InvalidStore()
        except BaseException:
            handle.close()
            raise
        handle.close()
        plain = b""
        for attempt in range(3):
            try:
                plain = self.decrypt_bytes(raw, source=os.fsdecode(file))
                break
            except AuthenticationFailed:
                if attempt == 2:
                    raise
        buffer = io.BytesIO(plain)
        buffer.name = os.fsdecode(file)
        return (
            buffer
            if binary
            else io.TextIOWrapper(
                buffer, encoding=encoding, errors=errors, newline=newline
            )
        )

    def enable(self) -> None:
        with self._mutex:
            self._check(self._generation)
            activate(self, self.open)

    def disable(self) -> None:
        deactivate(self)

    @contextmanager
    def activated(self):
        self.enable()
        try:
            yield self
        finally:
            self.disable()

    def _clear_keys(self) -> None:
        # Vault notifications hold its mutex. This callback acquires only the
        # cache mutex; code holding it must never call back into the vault.
        with self._key_mutex:
            keys, self._keys = self._keys, {}
            failure: type[SecurityError] | None = None
            interruption: BaseException | None = None
            for buffer in keys.values():
                try:
                    buffer.close()
                except SecurityError as exc:
                    failure = type(exc)
                except Exception:  # noqa: BLE001 -- still clear every owned buffer
                    failure = SecurityError
                except BaseException as exc:  # finish cleanup before cancellation
                    interruption = exc
            if interruption is not None:
                raise interruption
            if failure is not None:
                raise failure()

    def lock(self) -> None:
        with self._mutex:
            self._generation += 1
            try:
                self._clear_keys()
            finally:
                self._legacy.lock()
                if self._keystore is not None:
                    self._keystore.lock()

    def close(self) -> None:
        with self._mutex:
            if self._closed:
                return
            if self.active:
                self.disable()
            self._closed = True
            self.lock()
