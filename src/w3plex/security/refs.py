"""Local handles to encrypted data; never serialize these handles to an agent.

Public RPC callers use the separate SecretRef ID DTO in contracts. Native owned
buffers are cleared after use; Python and dependency copies remain a limitation.
"""

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Never, SupportsIndex, cast

from .contracts import SecretKind, SecretUse
from .contracts import SecretRef as SecretId
from .errors import (
    AuthenticationFailed,
    InteractionRequired,
    InvalidStore,
    PermissionDenied,
    SecurityError,
    UnsupportedProtection,
)
from .legacy import LegacyContext
from .memory import LockedBuffer
from .snapshots import _snapshot_file
from .vault import Vault
from .vault_format import _invalid_constant, _unique, canonical

MAX_SNAPSHOT_SIZE = 1024 * 1024
_SAFE_ERRORS = {
    AuthenticationFailed,
    InteractionRequired,
    InvalidStore,
    PermissionDenied,
    SecurityError,
    UnsupportedProtection,
}


def _safe[T](function: Callable[[], T]) -> T:
    error = SecurityError
    try:
        return function()
    except Exception as exc:  # noqa: BLE001 -- callback and parser errors are private
        if type(exc) in _SAFE_ERRORS:
            error = type(exc)
    raise error()


class AccessKind(StrEnum):
    USE = "use"
    DISCLOSE = "disclose"


@dataclass(frozen=True)
class SecretAccess:
    identifier: str
    action: AccessKind
    selection: str


@dataclass(frozen=True, repr=False)
class SecretRef[T]:
    _store: "SecretStore"
    _source: SecretId

    @property
    def identifier(self) -> str:
        return self._source.identifier

    @property
    def _selection(self) -> str:
        return self.identifier

    @property
    def _depth(self) -> int:
        return 0

    def __repr__(self) -> str:
        return f"{type(self).__name__}(<private>)"

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        raise PermissionDenied()

    def _restore(self, value: bytes) -> T:
        # The root handle's value is bytes. Typed children override this method.
        return cast(T, value)

    def _use[R](self, consumer: Callable[[T], R]) -> R:
        """Trusted consumer interface, not a model-facing operation."""
        return self._store._use(self, consumer)

    def ref(self, *, silent: bool = False) -> T:
        """Export ordinary plaintext. Default confirmation never displays it.

        silent suppresses that confirmation only. Exported Python values cannot
        be revoked or reliably erased by a later lock.
        """
        if type(silent) is not bool:
            raise PermissionDenied()
        return self._store._reveal(self, silent=silent)


def _bind_child(child: SecretRef, parent: SecretRef) -> None:
    if not isinstance(parent, SecretRef) or parent._depth >= 32:
        raise InvalidStore()
    object.__setattr__(child, "_store", parent._store)
    object.__setattr__(child, "_source", parent._source)
    object.__setattr__(child, "parent", parent)


@dataclass(frozen=True, repr=False, init=False)
class SecretString(SecretRef[str]):
    """A byte range in the parent's decoded bytes or encoded string value."""

    parent: SecretRef
    offset: int
    length: int | None
    encoding: str

    def __init__(
        self,
        parent: SecretRef,
        offset: int = 0,
        length: int | None = None,
        *,
        encoding: str = "utf-8",
    ):
        if (
            type(offset) is not int
            or offset < 0
            or (length is not None and (type(length) is not int or length < 0))
            or type(encoding) is not str
            or not 1 <= len(encoding) <= 64
        ):
            raise InvalidStore()
        _bind_child(self, parent)
        object.__setattr__(self, "offset", offset)
        object.__setattr__(self, "length", length)
        object.__setattr__(self, "encoding", encoding)

    @property
    def _depth(self) -> int:
        return self.parent._depth + 1

    @property
    def _selection(self) -> str:
        return hashlib.sha256(
            canonical(
                [
                    self.parent._selection,
                    "text",
                    self.offset,
                    self.length,
                    self.encoding,
                ]
            )
        ).hexdigest()

    def _restore(self, value: bytes) -> str:
        raw = self.parent._restore(value)
        if isinstance(raw, str):
            raw = raw.encode(self.encoding)
        if not isinstance(raw, bytes):
            raise InvalidStore()
        end = len(raw) if self.length is None else self.offset + self.length
        if not self.offset <= end <= len(raw):
            raise InvalidStore()
        return raw[self.offset : end].decode(self.encoding)


@dataclass(frozen=True, repr=False, init=False)
class SecretJson[T](SecretRef[T]):
    """A JSON value selected by a fixed path; no decoded document is retained."""

    parent: SecretRef
    path: tuple[str | int, ...]

    def __init__(self, parent: SecretRef, path: tuple[str | int, ...] = ()):
        path = tuple(path)
        if len(path) > 32 or any(
            not (type(key) is str or (type(key) is int and key >= 0)) for key in path
        ):
            raise InvalidStore()
        _bind_child(self, parent)
        object.__setattr__(self, "path", path)

    @property
    def _depth(self) -> int:
        return self.parent._depth + 1

    @property
    def _selection(self) -> str:
        return hashlib.sha256(
            canonical([self.parent._selection, "json", self.path])
        ).hexdigest()

    def __getitem__(self, key: str | int) -> "SecretJson[Any]":
        return SecretJson(self, (key,))

    def _restore(self, value: bytes) -> T:
        result = self.parent._restore(value)
        if isinstance(result, (str, bytes)):
            result = json.loads(
                result, object_pairs_hook=_unique, parse_constant=_invalid_constant
            )
        for key in self.path:
            if isinstance(key, str) and isinstance(result, dict):
                result = result[key]
                continue
            if isinstance(key, int) and isinstance(result, list):
                result = result[key]
                continue
            raise InvalidStore()
        return cast(T, result)


class SecretStore:
    """Capture input in an existing vault and bind private local references.

    The owner unlocks the vault or uses its existing Session. Optional host checks
    run at use time. Without an authorizer this is a trusted standalone interface;
    it is not an authentication boundary against code in its own Python process.
    """

    def __init__(
        self,
        vault: Vault,
        *,
        authorize: Callable[[SecretAccess], bool] | None = None,
        confirm: Callable[[SecretAccess], bool] | None = None,
        check: Callable[[], None] | None = None,
    ):
        self._vault = vault
        self._authorize = authorize
        self._confirm = confirm
        self._check_host = check

    def __repr__(self) -> str:
        return "SecretStore(<private>)"

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        raise PermissionDenied()

    def capture(self, value: bytes) -> SecretRef[bytes]:
        """Privately encrypt a snapshot before returning its immutable handle."""
        if not isinstance(value, bytes) or len(value) > MAX_SNAPSHOT_SIZE:
            raise InvalidStore()
        source = self._vault.add(SecretKind.DATA, value, uses=[SecretUse.DECRYPT])
        return SecretRef(self, source)

    def capture_file(
        self, filename: str | Path, *, legacy: LegacyContext | None = None
    ) -> SecretRef[bytes]:
        """Read once, decrypt legacy bytes privately, then encrypt in the vault.

        The host must approve sources before calling. No source path or input
        callback is retained by the resulting reference.
        """

        def operation():
            path = Path(filename).absolute()
            raw = _snapshot_file(path).raw
            if raw.startswith(b"ENC1"):
                if legacy is None:
                    raise InteractionRequired()
                raw = legacy.decrypt_bytes(raw, source=path)
            return self.capture(raw)

        return _safe(operation)

    def reference(self, identifier: str) -> SecretRef[bytes]:
        """Rebind a stored snapshot ID; authenticity is checked during use."""
        if (
            not isinstance(identifier, str)
            or len(identifier) != 32
            or any(c not in "0123456789abcdef" for c in identifier)
        ):
            raise PermissionDenied()
        return SecretRef(self, SecretId(identifier, SecretKind.DATA))

    def _stamp(self) -> LockedBuffer:
        if self._check_host is not None:
            self._check_host()
        self._vault._check()
        if self._vault._key is None or not self._vault.is_unlocked:
            raise PermissionDenied()
        return self._vault._key

    def _admit(self, reference: SecretRef, action: AccessKind) -> LockedBuffer:
        if reference._store is not self:
            raise PermissionDenied()
        with self._vault._mutex:
            stamp = self._stamp()
        if self._authorize is not None and (
            self._authorize(
                SecretAccess(reference.identifier, action, reference._selection)
            )
            is not True
        ):
            raise PermissionDenied()
        return stamp

    def _consume[T, R](
        self,
        reference: SecretRef[T],
        consumer: Callable[[T], R],
        stamp: LockedBuffer,
        *,
        action: AccessKind = AccessKind.USE,
    ) -> R:
        with self._vault._mutex:
            if (
                self._admit(reference, action) is not stamp
                or self._stamp() is not stamp
            ):
                raise PermissionDenied()

            def consume(value: bytes):
                if value:
                    with LockedBuffer(
                        value,
                        protection=self._vault._protection,
                        max_size=MAX_SNAPSHOT_SIZE,
                    ) as buffer:
                        result = consumer(reference._restore(buffer.copy_bytes()))
                else:
                    result = consumer(reference._restore(b""))
                if self._stamp() is not stamp:
                    raise PermissionDenied()
                return result

            return self._vault._use_secret(
                reference._source, SecretUse.DECRYPT, consume
            )

    def _use[T, R](self, reference: SecretRef[T], consumer: Callable[[T], R]) -> R:
        return _safe(
            lambda: self._consume(
                reference, consumer, self._admit(reference, AccessKind.USE)
            )
        )

    def _reveal[T](self, reference: SecretRef[T], *, silent: bool) -> T:
        def operation():
            stamp = self._admit(reference, AccessKind.DISCLOSE)
            if not silent:
                if self._confirm is None:
                    raise InteractionRequired()
                access = SecretAccess(
                    reference.identifier, AccessKind.DISCLOSE, reference._selection
                )
                if self._confirm(access) is not True:
                    raise PermissionDenied()
            return self._consume(
                reference, lambda value: value, stamp, action=AccessKind.DISCLOSE
            )

        return _safe(operation)
