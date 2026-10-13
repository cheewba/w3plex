"""Independent ENC1/KS01 readers; the old global API keeps its behavior.

Explicit reads are safe for separate service contexts. Activating built-in open
is process-wide and exclusive: unrelated threads/tasks must use explicit reads.
This reader has no agent/export API and never grants export permission.
"""

import base64
import builtins
import hashlib
import io
import json
import os
import threading
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from .errors import (
    ActivationConflict,
    AuthenticationFailed,
    InteractionRequired,
    InvalidStore,
    PermissionDenied,
)

_ACTIVATION_LOCK = threading.RLock()
_ACTIVE: "LegacyContext | None" = None
_HISTORICAL_N = (32768, 16384, 8192, 4096)
_MAX_STORE = 1024 * 1024
_MAX_FILE = 64 * 1024 * 1024


@dataclass(frozen=True, repr=False)
class LegacyPasswordRequest:
    kind: str
    source: Path

    def __repr__(self):
        return "LegacyPasswordRequest(<private>)"


class LegacyContext:
    _w3plex_security_context = True

    def __init__(
        self,
        keystore_path: str | Path | None,
        *,
        input_handler: Callable[[LegacyPasswordRequest], str] | None = None,
        opener: Callable[..., Any] = io.open,
    ):
        self.path = None if keystore_path is None else Path(keystore_path)
        self._input = input_handler
        self._opener = opener
        self._keys: list[bytes] | None = None
        self._previous: Any = None
        self._installed: Any = None
        self._lock = threading.RLock()
        self._epoch = 0

    def __repr__(self):
        return "LegacyContext(<private>)"

    def lock(self):
        with self._lock:
            self._keys = None
            self._epoch += 1

    @property
    def generation(self) -> int:
        with self._lock:
            return self._epoch

    def fork(self, *, input_handler: Callable[[LegacyPasswordRequest], str]):
        with self._lock:
            context = LegacyContext(
                self.path, input_handler=input_handler, opener=self._opener
            )
            context._keys = None if self._keys is None else list(self._keys)
            return self._epoch, context

    def merge(self, context: "LegacyContext", *, generation: int) -> None:
        with self._lock, context._lock:
            if self._epoch != generation or context.path != self.path:
                raise PermissionDenied()
            self._keys = None if context._keys is None else list(context._keys)

    def install_keys(self, keys: list[bytes]) -> None:
        if any(type(key) is not bytes or len(key) != 32 for key in keys):
            raise InvalidStore()
        with self._lock:
            self._keys = list(keys)

    def _password(self, kind: str, source: Path) -> str:
        if self._input is None:
            raise InteractionRequired()
        value = self._input(LegacyPasswordRequest(kind, source))
        if not isinstance(value, str):
            raise InteractionRequired()
        return value

    @staticmethod
    def parse_keys(plain: bytes) -> list[bytes]:
        valid = False
        keys: list[bytes] = []
        try:
            data = json.loads(plain)
            if (
                isinstance(data, dict)
                and set(data) == {"keys"}
                and isinstance(data["keys"], list)
                and len(data["keys"]) <= 4096
            ):
                for value in data["keys"]:
                    if not isinstance(value, str):
                        break
                    key = base64.b64decode(value, altchars=b"-_", validate=True)
                    if len(key) != 32:
                        break
                    keys.append(key)
                else:
                    valid = True
        except (ValueError, TypeError, UnicodeError):
            pass
        if not valid:
            raise InvalidStore()
        return keys

    def _read_keys(self) -> list[bytes]:
        if self._keys is not None:
            return self._keys
        if self.path is None:
            return []
        try:
            with self._opener(self.path, "rb") as stream:
                raw = stream.read(_MAX_STORE + 1)
        except FileNotFoundError:
            return []
        if not 16 <= len(raw) <= _MAX_STORE:
            raise InvalidStore()
        salt, payload = raw[:16], raw[16:]
        if not payload.startswith(b"KS01"):
            keys = self.parse_keys(payload)
        else:
            password = self._password("master", self.path)
            keys = None
            for n in _HISTORICAL_N:
                derived = hashlib.scrypt(
                    password.encode(),
                    salt=salt,
                    n=n,
                    r=8,
                    p=1,
                    dklen=32,
                    maxmem=128 * 1024 * 1024,
                )
                try:
                    plain = Fernet(base64.urlsafe_b64encode(derived)).decrypt(
                        payload[4:]
                    )
                except InvalidToken:
                    continue
                keys = self.parse_keys(plain)
                break
            if keys is None:
                raise AuthenticationFailed()
        self._keys = keys
        return keys

    def decrypt_bytes(self, raw: bytes, *, source: str | Path) -> bytes:
        """Trusted private read, not authorization to export its result.

        Newly entered file keys remain session-local. No store is rewritten.
        """
        if not raw.startswith(b"ENC1"):
            return raw
        if len(raw) > _MAX_FILE:
            raise InvalidStore()
        with self._lock:
            token = raw[4:]
            keys = self._read_keys()
            for key in keys:
                try:
                    return Fernet(base64.urlsafe_b64encode(key)).decrypt(token)
                except InvalidToken:
                    continue
            password = self._password("file", Path(source))
            key = hashlib.sha256(password.encode()).digest()
            success = False
            plain = b""
            try:
                plain = Fernet(base64.urlsafe_b64encode(key)).decrypt(token)
                success = True
            except InvalidToken:
                pass
            if not success:
                raise AuthenticationFailed()
            self._keys = [*keys, key]
            return plain

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
            prefix = stream.read(4)
            handle.seek(0)
            if prefix != b"ENC1":
                return handle
            raw = stream.read(_MAX_FILE + 1)
        except BaseException:
            handle.close()
            raise
        handle.close()
        if len(raw) > _MAX_FILE:
            raise InvalidStore()
        plain = b""
        for attempt in range(3):
            try:
                plain = self.decrypt_bytes(raw, source=os.fsdecode(file))
                break
            except AuthenticationFailed:
                self.lock()
                if attempt == 2:
                    raise
        buf = io.BytesIO(plain)
        buf.name = str(file)
        return (
            buf
            if binary
            else io.TextIOWrapper(
                buf, encoding=encoding, errors=errors, newline=newline
            )
        )

    def enable(self):
        global _ACTIVE
        with _ACTIVATION_LOCK:
            if _ACTIVE is not None or getattr(
                getattr(builtins.open, "__self__", None),
                "_w3plex_security_context",
                False,
            ):
                raise ActivationConflict()
            self._previous = builtins.open
            self._installed = self.open
            builtins.open = self._installed
            _ACTIVE = self

    def disable(self):
        global _ACTIVE
        with _ACTIVATION_LOCK:
            if _ACTIVE is not self or builtins.open is not self._installed:
                raise ActivationConflict()
            builtins.open = self._previous
            self._previous = self._installed = None
            _ACTIVE = None

    @contextmanager
    def activated(self):
        self.enable()
        try:
            yield self
        finally:
            self.disable()
