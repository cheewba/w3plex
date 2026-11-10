"""Instance-scoped ENC1/KS01 support, without import-time activation.

Ordinary contexts keep discovered keys in memory and never rewrite sources.
The CLI explicitly enables persistence of discovered keys.
These formats retain their historical protection; new protected storage uses Vault.
"""

import base64
import hashlib
import io
import json
import os
import secrets
import sys
import tempfile
import threading
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from ._io_activation import activate, deactivate, is_active
from ._streams import decrypted_stream
from .constants import (
    LEGACY_FILE_MAGIC,
    LEGACY_KEY_BYTES,
    LEGACY_SALT_BYTES,
    LEGACY_STORE_MAGIC,
    MAX_LEGACY_STORE_BYTES,
    PASSWORD_ENTROPY_BYTES,
)
from .errors import (
    AuthenticationFailed,
    InteractionRequired,
    InvalidStore,
    PermissionDenied,
)

# KS01 omitted its scrypt cost; readers try these historical N values in order.
_HISTORICAL_SCRYPT_N = (32768, 16384, 8192, 4096)
# Historical scrypt block-size parameter r, retained for KS01 compatibility.
_SCRYPT_BLOCK_SIZE = 8
# Historical scrypt parallelism parameter p, retained for KS01 compatibility.
_SCRYPT_PARALLELISM = 1
# Bound memory used while trying historical scrypt settings (128 MiB).
_SCRYPT_MAX_MEMORY_BYTES = 128 * 1024 * 1024
# Legacy key documents contain at most this many file keys.
_MAX_KEY_COUNT = 4096
# Maximum input or ciphertext accepted by the legacy file helpers (64 MiB).
_MAX_FILE_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True, repr=False)
class LegacyPasswordRequest:
    """Describe which legacy password is needed and its source file.

    Args:
        kind: One of master, master_confirm or file.
        source: Path or source name shown when requesting the password.
    """

    kind: str
    source: Path

    def __repr__(self):
        return "LegacyPasswordRequest(<private>)"


class LegacyContext:
    """Read and write ENC1/KS01 files with a separate cache of file keys."""

    _w3plex_security_context = True

    def __init__(
        self,
        keystore_path: str | Path | None,
        *,
        input_handler: Callable[[LegacyPasswordRequest], str] | None = None,
        opener: Callable[..., Any] = io.open,
        persist_keys: bool = False,
    ):
        """Set up legacy file reads without enabling them.

        Args:
            keystore_path: Path of a legacy key store, or None to use no file store.
            input_handler: Optional callback returning a password for a
                LegacyPasswordRequest.
            opener: Underlying open-compatible function used to access files.
            persist_keys: Whether to save newly found keys instead of keeping them only
                in memory.

        Returns:
            None.
        """
        self.path = None if keystore_path is None else Path(keystore_path)
        self._input = input_handler
        self._opener = opener
        self._persist_keys = persist_keys
        self._keys: list[bytes] | None = None
        self._salt: bytes | None = None
        self._master_key: bytes | None = None
        self._lock = threading.RLock()
        # Serialize workflows independently of lock(), including nested saves.
        # The state mutex must never be held across private input.
        self._operations = threading.RLock()
        self._epoch = 0

    def __repr__(self):
        return "LegacyContext(<private>)"

    def lock(self):
        """Clear cached keys and reject work from the previous session.

        Returns:
            None.
        """
        with self._lock:
            self._keys = self._salt = self._master_key = None
            self._epoch += 1

    @property
    def generation(self) -> int:
        """Return the number used to detect a session change.

        Returns:
            The current context generation. lock() increases this number.
        """
        with self._lock:
            return self._epoch

    @property
    def persist_keys(self) -> bool:
        """Check whether new file keys are saved.

        Returns:
            True if the context saves newly found file keys.
        """
        return self._persist_keys

    @property
    def active(self) -> bool:
        """Check whether this context controls builtins.open.

        Returns:
            True while this context owns the installed opener.
        """
        return is_active(self)

    def fork(self, *, input_handler: Callable[[LegacyPasswordRequest], str]):
        """Copy cached keys into a separate context for private input.

        Args:
            input_handler: Password callback used by the new context.

        Returns:
            A pair containing the parent generation and a context that does not save new
            keys.
        """
        with self._operations, self._lock:
            context = LegacyContext(
                self.path, input_handler=input_handler, opener=self._opener
            )
            context._keys = None if self._keys is None else list(self._keys)
            return self._epoch, context

    def merge(self, context: "LegacyContext", *, generation: int) -> None:
        """Copy discovered keys back if the parent session has not changed.

        Args:
            context: A working context returned by fork().
            generation: The parent generation returned by the same fork() call.

        Returns:
            None.
        """
        with self._operations, context._operations, self._lock, context._lock:
            if self._epoch != generation or context.path != self.path:
                raise PermissionDenied()
            self._keys = None if context._keys is None else list(context._keys)

    def install_keys(self, keys: list[bytes]) -> None:
        """Replace cached file keys with a copy of the given list.

        Args:
            keys: A list of 32-byte file keys.

        Returns:
            None.
        """
        if any(type(key) is not bytes or len(key) != LEGACY_KEY_BYTES for key in keys):
            raise InvalidStore()
        with self._operations, self._lock:
            self._keys = list(keys)

    def _check(self, generation: int) -> None:
        if self._epoch != generation:
            raise PermissionDenied()

    def _password(
        self, kind: str, source: Path, *, generation: int | None = None
    ) -> str:
        generation = self.generation if generation is None else generation
        with self._lock:
            self._check(generation)
            handler = self._input
            if handler is None:
                raise InteractionRequired()
        value = handler(LegacyPasswordRequest(kind, source))
        with self._lock:
            self._check(generation)
        if not isinstance(value, str):
            raise InteractionRequired()
        return value

    @staticmethod
    def parse_keys(plain: bytes) -> list[bytes]:
        """Check and decode a plain legacy key document.

        Args:
            plain: JSON bytes containing a keys list.

        Returns:
            The decoded 32-byte file keys.
        """
        valid = False
        keys: list[bytes] = []
        try:
            data = json.loads(plain)
            if (
                isinstance(data, dict)
                and set(data) == {"keys"}
                and isinstance(data.get("keys"), list)
                and len(data["keys"]) <= _MAX_KEY_COUNT
            ):
                for value in data["keys"]:
                    if not isinstance(value, str):
                        break
                    key = base64.b64decode(value, altchars=b"-_", validate=True)
                    if len(key) != LEGACY_KEY_BYTES:
                        break
                    keys.append(key)
                else:
                    valid = True
        except (ValueError, TypeError, UnicodeError):
            pass
        if not valid:
            raise InvalidStore()
        return keys

    def _raw_store(self) -> bytes | None:
        if self.path is None:
            return None
        try:
            with self._opener(self.path, "rb") as stream:
                raw = stream.read(MAX_LEGACY_STORE_BYTES + 1)
        except FileNotFoundError:
            return None
        if len(raw) < LEGACY_SALT_BYTES:
            raise InvalidStore()
        if len(raw) > MAX_LEGACY_STORE_BYTES:
            raise InvalidStore()
        return raw

    def _read_keys(self, generation: int, *, keep_master: bool = False) -> list[bytes]:
        with self._lock:
            self._check(generation)
            if self._keys is not None and not keep_master:
                return list(self._keys)
        raw = self._raw_store()
        with self._lock:
            self._check(generation)
        if raw is None:
            return []
        salt, payload = raw[:LEGACY_SALT_BYTES], raw[LEGACY_SALT_BYTES:]
        derived = None
        if not payload.startswith(LEGACY_STORE_MAGIC):
            keys = self.parse_keys(payload)
        else:
            assert self.path is not None
            password = self._password("master", self.path, generation=generation)
            try:
                keys, derived = _decode_keystore(raw, password)
            except AuthenticationFailed:
                with self._lock:
                    self._check(generation)
                    self._master_key = None
                raise
        with self._lock:
            self._check(generation)
            self._salt, self._keys = salt, keys
            if derived is not None and (self._persist_keys or keep_master):
                self._master_key = derived
            return keys

    def unlock_keystore(self) -> None:
        """Prepare and unlock the selected key store.

        Returns:
            None.
        """
        generation = self.generation
        with self._operations:
            self._unlock_keystore(generation)

    def _unlock_keystore(self, generation: int) -> None:
        with self._lock:
            self._check(generation)
            if self._master_key is not None:
                return
            if self.path is None:
                raise InvalidStore()
        raw = self._raw_store()
        with self._lock:
            self._check(generation)
            salt = raw[:LEGACY_SALT_BYTES] if raw is not None else self._salt
        if raw is not None and raw[LEGACY_SALT_BYTES:].startswith(LEGACY_STORE_MAGIC):
            self._read_keys(generation, keep_master=True)
            return
        password = self._password("master", self.path, generation=generation)
        if raw is None and password != self._password(
            "master_confirm", self.path, generation=generation
        ):
            raise AuthenticationFailed()
        if salt is None:
            salt = os.urandom(LEGACY_SALT_BYTES)
        # KS01 omitted work settings. Retain its historical adaptive writer.
        for n in _HISTORICAL_SCRYPT_N:
            try:
                derived = hashlib.scrypt(
                    password.encode(),
                    salt=salt,
                    n=n,
                    r=_SCRYPT_BLOCK_SIZE,
                    p=_SCRYPT_PARALLELISM,
                    dklen=LEGACY_KEY_BYTES,
                )
                with self._lock:
                    self._check(generation)
                    self._salt, self._master_key = salt, derived
                return
            except ValueError as error:
                if not any(
                    message in str(error).lower()
                    for message in ("memory limit exceeded", "not enough memory")
                ):
                    raise
        raise MemoryError("Unable to derive master key: scrypt N fell below 2**12")

    def _save_keys(self, keys: list[bytes], *, generation: int) -> None:
        if len(keys) > _MAX_KEY_COUNT:
            raise InvalidStore()
        self._unlock_keystore(generation)
        with self._lock:
            self._check(generation)
            path, salt, master_key = self.path, self._salt, self._master_key
            assert path is not None and salt is not None and master_key is not None
        data = json.dumps(
            {"keys": [base64.urlsafe_b64encode(key).decode() for key in keys]}
        ).encode()
        ciphertext = (
            salt
            + LEGACY_STORE_MAGIC
            + Fernet(base64.urlsafe_b64encode(master_key)).encrypt(data)
        )
        with self._lock:
            self._check(generation)
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(
            prefix="." + path.name + ".", dir=path.parent
        )
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(ciphertext)
                stream.flush()
                os.fsync(stream.fileno())
            with self._lock:
                self._check(generation)
                os.replace(temporary, path)
                self._check(generation)
                self._keys = list(keys)
        except BaseException:
            self.lock()
            raise
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass

    def _add_key(self, key: bytes, *, persist: bool, generation: int) -> None:
        keys = self._read_keys(generation)
        if key not in keys:
            updated = [*keys, key]
            if persist:
                self._save_keys(updated, generation=generation)
            else:
                with self._lock:
                    self._check(generation)
                    self._keys = updated
        elif persist and not self._persist_keys:
            self._save_keys(keys, generation=generation)

    def _encrypt_bytes(
        self, data: bytes, password: str, *, add_to_keystore: bool
    ) -> bytes:
        if len(data) > _MAX_FILE_BYTES:
            raise InvalidStore()
        generation = self.generation
        with self._operations:
            with self._lock:
                self._check(generation)
            key = hashlib.sha256(password.encode()).digest()
            ciphertext = LEGACY_FILE_MAGIC + Fernet(
                base64.urlsafe_b64encode(key)
            ).encrypt(data)
            if len(ciphertext) > _MAX_FILE_BYTES:
                raise InvalidStore()
            if add_to_keystore:
                self._add_key(key, persist=True, generation=generation)
            with self._lock:
                self._check(generation)
                return ciphertext

    def _decrypt_bytes(
        self,
        raw: bytes,
        *,
        source: str | Path,
        password: str | None = None,
        use_keystore: bool = True,
        ask_password: bool = True,
    ) -> bytes:
        if not raw.startswith(LEGACY_FILE_MAGIC):
            raise ValueError(f"{source} is not encrypted")
        if len(raw) > _MAX_FILE_BYTES:
            raise InvalidStore()
        generation = self.generation
        with self._operations:
            with self._lock:
                self._check(generation)
            token = raw[len(LEGACY_FILE_MAGIC) :]

            # Try cached file keys before requesting a password.
            if use_keystore and not password:
                for key in self._read_keys(generation):
                    try:
                        plain = Fernet(base64.urlsafe_b64encode(key)).decrypt(token)
                        with self._lock:
                            self._check(generation)
                            return plain
                    except InvalidToken:
                        continue

            if password:
                key = hashlib.sha256(password.encode()).digest()
            elif ask_password:
                key = hashlib.sha256(
                    self._password("file", Path(source), generation=generation).encode()
                ).digest()
            else:
                raise AuthenticationFailed()

            success = False
            plain = b""
            try:
                plain = Fernet(base64.urlsafe_b64encode(key)).decrypt(token)
                success = True
            except InvalidToken:
                pass
            if not success:
                raise AuthenticationFailed()
            # Return keys and data only if the session has not changed.
            if not password and use_keystore:
                self._add_key(key, persist=self._persist_keys, generation=generation)
            with self._lock:
                self._check(generation)
                return plain

    def decrypt_bytes(
        self,
        raw: bytes,
        *,
        source: str | Path,
        password: str | None = None,
        use_keystore: bool = True,
        ask_password: bool = True,
    ) -> bytes:
        """Decrypt ENC1 data and leave other bytes unchanged.

        Args:
            raw: Source bytes to inspect and decrypt.
            source: Source name used in password requests. This path is not opened here.
            password: Optional file password. If given, stored key lookup is skipped.
            use_keystore: Whether to allow saved or cached keys when no password is
                given.
            ask_password: Whether to ask for a missing file password.

        Returns:
            The decrypted bytes, or the original raw input if it is plain.
        """
        return (
            self._decrypt_bytes(
                raw,
                source=source,
                password=password,
                use_keystore=use_keystore,
                ask_password=ask_password,
            )
            if raw.startswith(LEGACY_FILE_MAGIC)
            else raw
        )

    def _read_file(self, source: Path) -> bytes:
        with source.open("rb") as stream:
            return stream.read(_MAX_FILE_BYTES + 1)

    def encrypt_file(
        self,
        src: str | Path,
        *,
        password: str | None = None,
        dst: str | Path | None = None,
        inplace: bool = False,
        add_to_keystore: bool = False,
    ) -> Path:
        """Encrypt a file and return the output path.

        Args:
            src: Path of the source file.
            password: File password. None requests a password through the input
                callback.
            dst: Output path. None uses the source path with .enc added.
            inplace: If True, replace the source file instead of writing to dst.
            add_to_keystore: Whether to save the file key for later reads.

        Returns:
            The path of the encrypted output file.
        """
        source = Path(src)
        data = self._read_file(source)
        if data.startswith(LEGACY_FILE_MAGIC):
            raise ValueError(f"{source} is already encrypted")
        password = password or self._password("file", source)
        ciphertext = self._encrypt_bytes(
            data, password, add_to_keystore=add_to_keystore
        )
        destination = (
            source
            if inplace
            else (Path(dst) if dst else source.with_suffix(source.suffix + ".enc"))
        )
        destination.write_bytes(ciphertext)
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
        """Decrypt a file and write its output.

        Args:
            src: Path of the encrypted source file.
            password: File password. None uses key lookup or the input callback.
            dst: Output path. None uses the source path with a .dec suffix.
            inplace: If True, replace the source file instead of writing to dst.
            use_keystore: Whether saved keys can be used when no password is given.

        Returns:
            The path of the decrypted output file.
        """
        source = Path(src)
        plain = self._decrypt_bytes(
            self._read_file(source),
            source=source,
            password=password,
            use_keystore=use_keystore,
        )
        destination = (
            source if inplace else (Path(dst) if dst else source.with_suffix(".dec"))
        )
        destination.write_bytes(plain)
        return destination

    def encrypt_data(
        self,
        data: str | bytes,
        *,
        password: str | None = None,
        add_to_keystore: bool = True,
    ) -> tuple[str, str]:
        """Encrypt bytes or text and return its file password.

        Args:
            data: Bytes or text to encrypt. Text is encoded as UTF-8.
            password: File password. None creates a random password when key saving is
                enabled.
            add_to_keystore: Whether to save the key for later reads.

        Returns:
            A pair containing base64 encrypted text and the password used.
        """
        if password is None and not add_to_keystore:
            raise ValueError(
                "Either password must be provided or add_to_keystore must be True"
            )
        if isinstance(data, str):
            data = data.encode("utf-8")
        if password is None:
            password = secrets.token_urlsafe(PASSWORD_ENTROPY_BYTES)
        ciphertext = self._encrypt_bytes(
            data, password, add_to_keystore=add_to_keystore
        )
        return base64.b64encode(ciphertext).decode("ascii"), password

    def decrypt_data(
        self, encrypted: str, *, password: str | None = None, use_keystore: bool = True
    ) -> str:
        """Decrypt recognized base64 input as UTF-8 text.

        Args:
            encrypted: Base64 text containing encrypted data.
            password: Optional file password. Without it, saved keys may be used.
            use_keystore: Whether to allow saved keys when no password is given.

        Returns:
            Decrypted text for a supported container, otherwise the original input
            string.
        """
        try:
            raw = base64.b64decode(encrypted.encode("ascii"))
        except (ValueError, UnicodeEncodeError):
            raise ValueError("Invalid base64-encoded data") from None
        if not raw.startswith(LEGACY_FILE_MAGIC):
            return encrypted
        return self._decrypt_bytes(
            raw,
            source="encrypted data",
            password=password,
            use_keystore=use_keystore,
            ask_password=False,
        ).decode("utf-8")

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
        """Open files normally and decrypt supported read-only files.

        Args:
            file: A path or file descriptor, as accepted by builtins.open.
            mode: Open mode. Only read-only file paths are decrypted; other modes pass
                through.
            buffering: Buffer size passed to the underlying file opener.
            encoding: Encoding used to read decrypted bytes as text.
            errors: How text decoding errors are handled.
            newline: How line endings are handled in text mode.
            closefd: Whether closing a stream also closes its file descriptor.
            opener: Optional low-level file-opening callback, as in builtins.open.

        Returns:
            A file-like stream. The caller must close it.
        """

        def on_failure(kind, remaining):
            if not self._persist_keys:
                self.lock()
            elif remaining:
                sys.stdout.write(f"Incorrect password, {remaining} attempts left\r\n")
                sys.stdout.flush()

        handle = self._opener(
            file, mode, buffering, encoding, errors, newline, closefd, opener
        )
        return decrypted_stream(
            handle,
            file=file,
            mode=mode,
            encoding=encoding,
            errors=errors,
            newline=newline,
            maximum_size=_MAX_FILE_BYTES,
            detect=lambda prefix: (
                "legacy" if prefix.startswith(LEGACY_FILE_MAGIC) else "plain"
            ),
            decrypt=self.decrypt_bytes,
            on_failure=on_failure,
            name=str(file),
        )

    def enable(self):
        """Install this context as the built-in file opener.

        Returns:
            None.
        """
        activate(self, self.open)

    def disable(self):
        """Restore the file opener used before this context.

        Returns:
            None.
        """
        deactivate(self)

    @contextmanager
    def activated(self):
        """Use this file opener within a with block.

        Returns:
            A context manager that yields this context and restores the previous opener
            on exit.
        """
        self.enable()
        try:
            yield self
        finally:
            self.disable()


def _decode_keystore(
    raw: bytes, password: str | None
) -> tuple[list[bytes], bytes | None]:
    if (
        type(raw) is not bytes
        or not LEGACY_SALT_BYTES <= len(raw) <= MAX_LEGACY_STORE_BYTES
    ):
        raise InvalidStore()
    salt, payload = raw[:LEGACY_SALT_BYTES], raw[LEGACY_SALT_BYTES:]
    if not payload.startswith(LEGACY_STORE_MAGIC):
        return LegacyContext.parse_keys(payload), None
    if password is None:
        raise InteractionRequired()
    for n in _HISTORICAL_SCRYPT_N:
        derived = hashlib.scrypt(
            password.encode(),
            salt=salt,
            n=n,
            r=_SCRYPT_BLOCK_SIZE,
            p=_SCRYPT_PARALLELISM,
            dklen=LEGACY_KEY_BYTES,
            maxmem=_SCRYPT_MAX_MEMORY_BYTES,
        )
        try:
            plain = Fernet(base64.urlsafe_b64encode(derived)).decrypt(
                payload[len(LEGACY_STORE_MAGIC) :]
            )
        except InvalidToken:
            continue
        return LegacyContext.parse_keys(plain), derived
    raise AuthenticationFailed()


def decode_keystore(raw: bytes, password: str | None = None) -> list[bytes]:
    """Read captured legacy key-store bytes without opening a file.

    Args:
        raw: Complete legacy store bytes, including the salt.
        password: Master password for KS01 input. Plain stores do not need it.

    Returns:
        The decoded file keys.
    """
    return _decode_keystore(raw, password)[0]
