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

from .errors import (
    AuthenticationFailed,
    InteractionRequired,
    InvalidStore,
    PermissionDenied,
)
from .io_activation import activate, deactivate, is_active

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
        persist_keys: bool = False,
    ):
        self.path = None if keystore_path is None else Path(keystore_path)
        self._input = input_handler
        self._opener = opener
        self._persist_keys = persist_keys
        self._keys: list[bytes] | None = None
        self._salt: bytes | None = None
        self._master_key: bytes | None = None
        self._lock = threading.RLock()
        self._epoch = 0

    def __repr__(self):
        return "LegacyContext(<private>)"

    def lock(self):
        with self._lock:
            self._keys = self._salt = self._master_key = None
            self._epoch += 1

    @property
    def generation(self) -> int:
        with self._lock:
            return self._epoch

    @property
    def persist_keys(self) -> bool:
        return self._persist_keys

    @property
    def active(self) -> bool:
        return is_active(self)

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
                and isinstance(data.get("keys"), list)
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

    def _raw_store(self) -> bytes | None:
        if self.path is None:
            return None
        try:
            with self._opener(self.path, "rb") as stream:
                raw = stream.read(_MAX_STORE + 1)
        except FileNotFoundError:
            return None
        if len(raw) < 16:
            raise InvalidStore()
        if len(raw) > _MAX_STORE:
            raise InvalidStore()
        return raw

    def _read_keys(self, *, keep_master: bool = False) -> list[bytes]:
        if self._keys is not None and not keep_master:
            return self._keys
        raw = self._raw_store()
        if raw is None:
            return []
        self._salt, payload = raw[:16], raw[16:]
        if not payload.startswith(b"KS01"):
            keys = self.parse_keys(payload)
        else:
            assert self.path is not None
            password = self._password("master", self.path)
            try:
                keys, derived = _decode_keystore(raw, password)
            except AuthenticationFailed:
                self._master_key = None
                raise
            if self._persist_keys or keep_master:
                self._master_key = derived
        self._keys = keys
        return keys

    def unlock_keystore(self) -> None:
        with self._lock:
            if self._master_key is not None:
                return
            if self.path is None:
                raise InvalidStore()
            raw = self._raw_store()
            if raw is not None:
                self._salt = raw[:16]
                if raw[16:].startswith(b"KS01"):
                    self._read_keys(keep_master=True)
                    return
            password = self._password("master", self.path)
            if raw is None and password != self._password("master_confirm", self.path):
                raise AuthenticationFailed()
            if self._salt is None:
                self._salt = os.urandom(16)
            # KS01 omitted work settings. Retain its historical adaptive writer.
            for n in _HISTORICAL_N:
                try:
                    self._master_key = hashlib.scrypt(
                        password.encode(), salt=self._salt, n=n, r=8, p=1, dklen=32
                    )
                    return
                except ValueError as error:
                    if not any(
                        message in str(error).lower()
                        for message in ("memory limit exceeded", "not enough memory")
                    ):
                        raise
            raise MemoryError("Unable to derive master key: scrypt N fell below 2**12")

    def _save_keys(self, keys: list[bytes]) -> None:
        if len(keys) > 4096:
            raise InvalidStore()
        self.unlock_keystore()
        assert (
            self.path is not None
            and self._salt is not None
            and self._master_key is not None
        )
        data = json.dumps(
            {"keys": [base64.urlsafe_b64encode(key).decode() for key in keys]}
        ).encode()
        ciphertext = (
            self._salt
            + b"KS01"
            + Fernet(base64.urlsafe_b64encode(self._master_key)).encrypt(data)
        )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(
            prefix="." + self.path.name + ".", dir=self.path.parent
        )
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(ciphertext)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
        except BaseException:
            self.lock()
            raise
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
        self._keys = list(keys)

    def _add_key(self, key: bytes, *, persist: bool) -> None:
        keys = self._read_keys()
        if key not in keys:
            updated = [*keys, key]
            if persist:
                self._save_keys(updated)
            else:
                self._keys = updated
        elif persist and not self._persist_keys:
            self._save_keys(keys)

    def _encrypt_bytes(
        self, data: bytes, password: str, *, add_to_keystore: bool
    ) -> bytes:
        if len(data) > _MAX_FILE:
            raise InvalidStore()
        with self._lock:
            key = hashlib.sha256(password.encode()).digest()
            ciphertext = b"ENC1" + Fernet(base64.urlsafe_b64encode(key)).encrypt(data)
            if len(ciphertext) > _MAX_FILE:
                raise InvalidStore()
            if add_to_keystore:
                self._add_key(key, persist=True)
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
        if not raw.startswith(b"ENC1"):
            raise ValueError(f"{source} is not encrypted")
        if len(raw) > _MAX_FILE:
            raise InvalidStore()
        with self._lock:
            token = raw[4:]
            if use_keystore and not password:
                for key in self._read_keys():
                    try:
                        return Fernet(base64.urlsafe_b64encode(key)).decrypt(token)
                    except InvalidToken:
                        continue
            if password:
                key = hashlib.sha256(password.encode()).digest()
            elif ask_password:
                key = hashlib.sha256(
                    self._password("file", Path(source)).encode()
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
            if not password and use_keystore:
                self._add_key(key, persist=self._persist_keys)
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
        """Private read; ordinary contexts never rewrite the source keystore."""
        return (
            self._decrypt_bytes(
                raw,
                source=source,
                password=password,
                use_keystore=use_keystore,
                ask_password=ask_password,
            )
            if raw.startswith(b"ENC1")
            else raw
        )

    def _read_file(self, source: Path) -> bytes:
        with source.open("rb") as stream:
            return stream.read(_MAX_FILE + 1)

    def encrypt_file(
        self,
        src: str | Path,
        *,
        password: str | None = None,
        dst: str | Path | None = None,
        inplace: bool = False,
        add_to_keystore: bool = False,
    ) -> Path:
        source = Path(src)
        data = self._read_file(source)
        if data.startswith(b"ENC1"):
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
        if password is None and not add_to_keystore:
            raise ValueError(
                "Either password must be provided or add_to_keystore must be True"
            )
        if isinstance(data, str):
            data = data.encode("utf-8")
        if password is None:
            password = secrets.token_urlsafe(32)
        ciphertext = self._encrypt_bytes(
            data, password, add_to_keystore=add_to_keystore
        )
        return base64.b64encode(ciphertext).decode("ascii"), password

    def decrypt_data(
        self, encrypted: str, *, password: str | None = None, use_keystore: bool = True
    ) -> str:
        try:
            raw = base64.b64decode(encrypted.encode("ascii"))
        except (ValueError, UnicodeEncodeError):
            raise ValueError("Invalid base64-encoded data") from None
        if not raw.startswith(b"ENC1"):
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
                if not self._persist_keys:
                    self.lock()
                if attempt == 2:
                    raise
                if self._persist_keys:
                    sys.stdout.write(
                        f"Incorrect password, {2 - attempt} attempts left\r\n"
                    )
                    sys.stdout.flush()
        buffer = io.BytesIO(plain)
        buffer.name = str(file)
        return (
            buffer
            if binary
            else io.TextIOWrapper(
                buffer, encoding=encoding, errors=errors, newline=newline
            )
        )

    def enable(self):
        activate(self, self.open)

    def disable(self):
        deactivate(self)

    @contextmanager
    def activated(self):
        self.enable()
        try:
            yield self
        finally:
            self.disable()


def _decode_keystore(
    raw: bytes, password: str | None
) -> tuple[list[bytes], bytes | None]:
    if type(raw) is not bytes or not 16 <= len(raw) <= _MAX_STORE:
        raise InvalidStore()
    salt, payload = raw[:16], raw[16:]
    if not payload.startswith(b"KS01"):
        return LegacyContext.parse_keys(payload), None
    if password is None:
        raise InteractionRequired()
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
            plain = Fernet(base64.urlsafe_b64encode(derived)).decrypt(payload[4:])
        except InvalidToken:
            continue
        return LegacyContext.parse_keys(plain), derived
    raise AuthenticationFailed()


def decode_keystore(raw: bytes, password: str | None = None) -> list[bytes]:
    """Decode a bounded captured KS01/plain legacy store without filesystem I/O."""
    return _decode_keystore(raw, password)[0]
