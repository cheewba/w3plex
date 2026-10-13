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
from typing import Any, Never, Self, SupportsIndex, cast

from .contracts import SecretKind, SecretRef as SecretId, SecretUse
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
from .snapshots import snapshot_file
from .vault import Vault
from .vault_format import canonical, reject_json_constant, unique_fields

MAX_SNAPSHOT_SIZE = 1024 * 1024
_SAFE_ERRORS = {
    AuthenticationFailed,
    InteractionRequired,
    InvalidStore,
    PermissionDenied,
    SecurityError,
    UnsupportedProtection,
}


def safe_call[T](function: Callable[[], T]) -> T:
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
    def kind(self) -> SecretKind:
        return self._source.kind

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

    def __deepcopy__(self, memo: dict[int, Any]) -> Self:
        # Configuration copies retain this immutable local handle and its owner.
        memo[id(self)] = self
        return self

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
                result,
                object_pairs_hook=unique_fields,
                parse_constant=reject_json_constant,
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

    def capture(
        self, value: bytes, *, kind: SecretKind = SecretKind.DATA
    ) -> SecretRef[bytes]:
        """Privately encrypt a snapshot before returning its immutable handle."""
        if (
            not isinstance(value, bytes)
            or len(value) > MAX_SNAPSHOT_SIZE
            or not isinstance(kind, SecretKind)
            or kind
            not in {SecretKind.DATA, SecretKind.API, SecretKind.RPC, SecretKind.MODEL}
        ):
            raise InvalidStore()
        purpose = SecretUse.DECRYPT if kind is SecretKind.DATA else SecretUse.HTTP
        source = self._vault.add(kind, value, uses=[purpose])
        return SecretRef(self, source)

    def credential(
        self, reference: SecretRef, *, kind: SecretKind = SecretKind.API
    ) -> SecretRef[bytes]:
        """Privately copy a selected field into a classified encrypted record."""
        if not isinstance(kind, SecretKind) or kind not in {
            SecretKind.API,
            SecretKind.RPC,
            SecretKind.MODEL,
        }:
            raise InvalidStore()

        def capture(value):
            return self.capture(
                value.encode("utf-8") if isinstance(value, str) else value, kind=kind
            )

        return reference._use(capture)

    def capture_file(
        self, filename: str | Path, *, legacy: LegacyContext | None = None
    ) -> SecretRef[bytes]:
        """Read once, decrypt legacy bytes privately, then encrypt in the vault.

        The host must approve sources before calling. No source path or input
        callback is retained by the resulting reference.
        """

        def operation():
            with self._vault._mutex:
                stamp = self._stamp()
            path = Path(filename).absolute()
            raw = snapshot_file(path).raw
            if raw.startswith(b"ENC1"):
                if legacy is None:
                    raise InteractionRequired()
                raw = legacy.decrypt_bytes(raw, source=path)
            with self._vault._mutex:
                if self._stamp() is not stamp:
                    raise PermissionDenied()
                return self.capture(raw)

        return safe_call(operation)

    def reference(
        self, identifier: str, *, kind: SecretKind = SecretKind.DATA
    ) -> SecretRef[bytes]:
        """Rebind a stored snapshot ID; authenticity is checked during use."""
        if (
            not isinstance(identifier, str)
            or len(identifier) != 32
            or any(c not in "0123456789abcdef" for c in identifier)
            or not isinstance(kind, SecretKind)
            or kind
            not in {SecretKind.DATA, SecretKind.API, SecretKind.RPC, SecretKind.MODEL}
        ):
            raise PermissionDenied()
        return SecretRef(self, SecretId(identifier, kind))

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

            purpose = (
                SecretUse.DECRYPT
                if reference.kind is SecretKind.DATA
                else SecretUse.HTTP
            )
            return self._vault._use_secret(reference._source, purpose, consume)

    def _use[T, R](self, reference: SecretRef[T], consumer: Callable[[T], R]) -> R:
        return safe_call(
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

        return safe_call(operation)
