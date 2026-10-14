"""Shared transparent reads of ordinary, ENC1 and W3FILE1 inputs."""

import base64
import hashlib
import io
import os
import secrets
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
from .migration import migrate_keystore
from .snapshots import snapshot_file
from .storage import CiphertextFile, FileIdentity, StoreChanged
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
        protection: ProcessProtection | None = None,
        input_handler: Callable[[PasswordRequest], str] | None = None,
        legacy_keystore_path: str | Path | None = None,
        persist_legacy_keys: bool = False,
        keystore: Vault | None = None,
        keystore_path: str | Path | None = None,
        persist_keys: bool = False,
        opener: Callable[..., Any] = io.open,
    ):
        if (
            type(persist_keys) is not bool
            or (keystore is not None and keystore_path is not None)
            or (persist_keys and keystore is None and keystore_path is None)
        ):
            raise InvalidStore()
        self._protection = protection or ProcessProtection()
        self._own_protection = protection is None
        self._protection_started = False
        self._keystore = keystore
        self._keystore_path = (
            None if keystore_path is None else Path(keystore_path).absolute()
        )
        self._own_keystore = keystore_path is not None
        self._keystore_bound = keystore is not None
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
        self._prepare_mutex = threading.RLock()
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

    def _check_protection(self) -> None:
        with self._mutex:
            if self._own_protection and not self._protection_started:
                self._protection.activate()
                self._protection_started = True
            self._protection.check()

    def file_password(self, source: str | Path) -> str:
        """Trusted explicit CLI input, after required modern process controls."""
        self._check_protection()
        generation = self.generation
        value = self._password("file", source)
        with self._mutex:
            self._check(generation)
        return value

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
        self._check_protection()
        self._prepare_keystore(create=True, generation=generation)
        keystore = self._keystore
        if keystore is None:
            raise InteractionRequired()
        if keystore.is_unlocked:
            with self._mutex:
                self._check(generation)
                if not self._keystore_bound:
                    keystore.add_lock_listener(self._clear_keys)
                    self._keystore_bound = True
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
            if not self._keystore_bound:
                keystore.add_lock_listener(self._clear_keys)
                self._keystore_bound = True

    def _prepare_keystore(self, *, create: bool, generation: int) -> None:
        # Serialize preparation without blocking lock() during private input.
        with self._prepare_mutex:
            with self._mutex:
                self._check(generation)
                if self._keystore is not None or self._keystore_path is None:
                    return
                path = self._keystore_path
            if not create and not path.exists():
                return
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            storage = CiphertextFile(path)
            vault = None

            def check():
                with self._mutex:
                    self._check(generation)
                    self._protection.check()

            try:
                if storage.identity() is not None:
                    raw, _ = storage.read()
                    if not raw.startswith(b"W3VAULT"):
                        vault = private_call(
                            lambda: migrate_keystore(
                                storage,
                                path.with_name(path.name + ".legacy.bak"),
                                protection=self._protection,
                                password=self._password,
                                check=check,
                            )
                        )
                with self._mutex:
                    check()
                    if vault is None:
                        vault = Vault(storage, protection=self._protection)
                    else:
                        self._legacy.lock()
                        vault.add_lock_listener(self._clear_keys)
                        self._keystore_bound = True
                    self._keystore = vault
            except BaseException:
                if vault is not None:
                    vault.close()
                else:
                    storage.close()
                raise

    def _store_available(self) -> bool:
        return self._keystore is not None or (
            self._keystore_path is not None and self._keystore_path.exists()
        )

    def _decrypt_legacy_from_vault(
        self,
        raw: bytes,
        *,
        source: str | Path,
        password: str | None,
        ask_password: bool,
    ) -> bytes:
        generation = self.generation
        self._check_protection()
        self._prepare_keystore(create=False, generation=generation)
        self.unlock_keystore()
        keystore = self._keystore
        if keystore is None:
            raise InteractionRequired()
        epoch = keystore.checkpoint()
        keys = [
            keystore.read(identifier)
            for identifier in keystore.find_metadata({"context": "w3plex.legacy-file"})
        ]
        candidate = (
            None if password is None else hashlib.sha256(password.encode()).digest()
        )

        def answer(request):
            nonlocal candidate
            entered = self._legacy_password(request)
            candidate = hashlib.sha256(entered.encode()).digest()
            return entered

        decoder = LegacyContext(None, input_handler=answer)
        decoder.install_keys(keys)
        try:
            value = decoder.decrypt_bytes(
                raw, source=source, password=password, ask_password=ask_password
            )
            with self._mutex, keystore.mutex:
                self._check(generation)
                self._check_keystore(epoch)
                self._check_protection()
                if (
                    self._persist_keys
                    and candidate is not None
                    and candidate not in keys
                ):
                    keystore.save(candidate, metadata={"context": "w3plex.legacy-file"})
            return value
        finally:
            decoder.lock()
            keys.clear()

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

    def _keystore_checkpoint(self) -> int | None:
        keystore = self._keystore
        if keystore is None:
            return None
        with keystore.mutex:
            return keystore.checkpoint() if keystore.is_unlocked else None

    def decrypt_bytes(
        self,
        raw: bytes,
        *,
        source: str | Path,
        password: str | None = None,
        use_keystore: bool = True,
        ask_password: bool = True,
    ) -> bytes:
        generation = self.generation
        kind = detect_format(raw)
        use_keystore = use_keystore and password is None
        with self._mutex:
            self._check(generation)
        if kind == "plain":
            return raw
        if kind == "legacy":
            if use_keystore and (
                self._store_available() or (self._persist_keys and ask_password)
            ):
                return self._decrypt_legacy_from_vault(
                    raw, source=source, password=password, ask_password=ask_password
                )
            value = self._legacy.decrypt_bytes(
                raw,
                source=source,
                password=password,
                use_keystore=use_keystore,
                ask_password=ask_password,
            )
            with self._mutex:
                self._check(generation)
            return value
        envelope = file_format.parse(raw)
        self._check_protection()
        if use_keystore:
            self._prepare_keystore(
                create=self._persist_keys and ask_password, generation=generation
            )
        if use_keystore and self._keystore is not None:
            self.unlock_keystore()
        store_generation = (
            None
            if self._keystore is None or not use_keystore
            else self._keystore.checkpoint()
        )
        fingerprint = hashlib.sha256(raw).hexdigest()
        with self._mutex:
            self._check(generation)
            with self._key_mutex:
                buffer = (
                    self._keys.get(fingerprint)
                    if password is None and use_keystore
                    else None
                )
                key = None if buffer is None else buffer.copy_bytes()
            if key is None and password is None and use_keystore:
                key = self._stored_key(fingerprint)
            with self._key_mutex:
                if key is None and len(self._keys) >= _MAXIMUM_KEYS:
                    raise InvalidStore()
        if key is None:
            if password is None and not ask_password:
                raise AuthenticationFailed()
            secret = self._password("file", source) if password is None else password
            with self._mutex:
                self._check(generation)
                if use_keystore:
                    self._check_keystore(store_generation)
            key = file_format.unwrap(envelope, secret.encode("utf-8"))
        value = file_format.open_payload(envelope, key)
        with (
            self._mutex,
            nullcontext() if self._keystore is None else self._keystore.mutex,
        ):
            self._check(generation)
            if use_keystore:
                self._check_keystore(store_generation)
            self._check_protection()
            if self._persist_keys and use_keystore and self._keystore is not None:
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

    def _encrypted(
        self,
        data: bytes,
        password: str,
        *,
        add_to_keystore: bool,
        store_generation: int | None = None,
    ) -> tuple[bytes, int | None]:
        generation = self.generation
        self._check_protection()
        if store_generation is None:
            store_generation = self._keystore_checkpoint()
        envelope, key = file_format.seal(data, password.encode("utf-8"))
        raw = envelope.serialize()
        if add_to_keystore:
            self.unlock_keystore()
            if store_generation is None:
                store_generation = self._keystore_checkpoint()
        with (
            self._mutex,
            nullcontext() if self._keystore is None else self._keystore.mutex,
        ):
            self._check(generation)
            if store_generation is not None or add_to_keystore:
                self._check_keystore(store_generation)
            fingerprint = hashlib.sha256(raw).hexdigest()
            if add_to_keystore:
                self._remember_key(fingerprint, key)
            else:
                with self._key_mutex:
                    if len(self._keys) >= _MAXIMUM_KEYS:
                        raise InvalidStore()
                    self._keys[fingerprint] = LockedBuffer(
                        key, protection=self._protection
                    )
        return raw, store_generation

    def encrypt_data(
        self,
        data: str | bytes,
        *,
        password: str | None = None,
        add_to_keystore: bool = True,
    ) -> tuple[str, str]:
        if password is None and not add_to_keystore:
            raise ValueError(
                "Either password must be provided or add_to_keystore must be True"
            )
        if isinstance(data, str):
            data = data.encode("utf-8")
        password = secrets.token_urlsafe(32) if password is None else password
        raw, _ = self._encrypted(data, password, add_to_keystore=add_to_keystore)
        return base64.b64encode(raw).decode("ascii"), password

    def decrypt_data(
        self, encrypted: str, *, password: str | None = None, use_keystore: bool = True
    ) -> str:
        raw = None
        try:
            raw = base64.b64decode(encrypted.encode("ascii"), validate=True)
        except (ValueError, UnicodeError):
            pass
        if raw is None:
            raise ValueError("Invalid base64-encoded data")
        if detect_format(raw) == "plain":
            return encrypted
        return self.decrypt_bytes(
            raw,
            source="encrypted data",
            password=password,
            use_keystore=use_keystore,
            ask_password=False,
        ).decode("utf-8")

    def encrypt_file(
        self,
        src: str | Path,
        *,
        password: str | None = None,
        dst: str | Path | None = None,
        inplace: bool = False,
        add_to_keystore: bool = False,
    ) -> Path:
        self._check_protection()
        generation = self.generation
        source = Path(src).absolute()
        snapshot = snapshot_file(source, maximum_size=file_format.MAXIMUM_PLAINTEXT)
        if detect_format(snapshot.raw) != "plain":
            raise ValueError("Source is already encrypted")
        destination = (
            Path(src)
            if inplace
            else Path(dst)
            if dst
            else Path(src).with_suffix(Path(src).suffix + ".enc")
        )
        with CiphertextFile(
            destination, maximum_size=file_format.MAXIMUM_SIZE
        ) as storage:
            expected = storage.identity()
            if storage.path == source and expected != FileIdentity(
                *snapshot.identity, hashlib.sha256(snapshot.raw).digest()
            ):
                raise StoreChanged()
            store_generation = self._keystore_checkpoint()
            secret = self._password("file", source) if password is None else password
            with self._mutex:
                self._check(generation)
            raw, store_generation = self._encrypted(
                snapshot.raw,
                secret,
                add_to_keystore=add_to_keystore,
                store_generation=store_generation,
            )
            with (
                self._mutex,
                nullcontext() if self._keystore is None else self._keystore.mutex,
            ):
                self._check(generation)
                if store_generation is not None:
                    self._check_keystore(store_generation)
                storage.write(raw, expected=expected)
        return destination

    def decrypt_file(
        self,
        src: str | Path,
        *,
        password: str | None = None,
        dst: str | Path | None = None,
        inplace: bool = False,
        use_keystore: bool = False,
    ) -> Path:
        generation = self.generation
        use_keystore = use_keystore and password is None
        source = Path(src).absolute()
        snapshot = snapshot_file(source, maximum_size=file_format.MAXIMUM_SIZE)
        kind = detect_format(snapshot.raw)
        if kind == "plain":
            raise ValueError("Source is not encrypted")
        destination = (
            Path(src)
            if inplace
            else Path(dst)
            if dst
            else Path(src).with_suffix(".dec")
        )
        with CiphertextFile(
            destination, maximum_size=file_format.MAXIMUM_SIZE
        ) as storage:
            expected = storage.identity()
            if storage.path == source and expected != FileIdentity(
                *snapshot.identity, hashlib.sha256(snapshot.raw).digest()
            ):
                raise StoreChanged()
            if kind == "modern":
                file_format.parse(snapshot.raw)
            store_generation = self._keystore_checkpoint()
            if use_keystore and (
                kind == "modern" or self._store_available() or self._persist_keys
            ):
                # Prepare before decryption so its vault epoch also covers the
                # plaintext commit. Never hold the vault mutex across input.
                self._check_protection()
                self._prepare_keystore(create=self._persist_keys, generation=generation)
                if self._keystore is not None:
                    self.unlock_keystore()
                    if store_generation is None:
                        store_generation = self._keystore_checkpoint()
            plaintext = self.decrypt_bytes(
                snapshot.raw,
                source=source,
                password=password,
                use_keystore=use_keystore,
            )
            with (
                self._mutex,
                nullcontext() if self._keystore is None else self._keystore.mutex,
            ):
                self._check(generation)
                if store_generation is not None:
                    self._check_keystore(store_generation)
                storage.write_plaintext(plaintext, expected=expected)
        return destination

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
                if kind == "legacy":
                    if not self._legacy.persist_keys:
                        self._legacy.lock()
                remaining = 2 - attempt
                suffix = "" if remaining == 1 else "s"
                print(f"Incorrect password, {remaining} attempt{suffix} left")
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
                except BaseException as exc:  # noqa: BLE001 -- finish cleanup before cancellation
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
            try:
                self.lock()
            finally:
                if self._own_keystore and self._keystore is not None:
                    self._keystore.close()
