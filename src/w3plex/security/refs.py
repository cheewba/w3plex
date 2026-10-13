"""Structural references to immutable encrypted data; no application policy."""

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    Any,
    Never,
    Protocol,
    Self,
    SupportsIndex,
    runtime_checkable,
)

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

if TYPE_CHECKING:
    from .adapters import (
        SecretJson as SecretJson,  # noqa: PLC0414 -- compatible re-export
        SecretString as SecretString,  # noqa: PLC0414 -- compatible re-export
    )

MAX_SNAPSHOT_SIZE = 1024 * 1024
_SAFE_ERRORS = {
    AuthenticationFailed,
    InteractionRequired,
    InvalidStore,
    PermissionDenied,
    SecurityError,
    UnsupportedProtection,
}


@runtime_checkable
class ISecretRef[T](Protocol):
    def ref(self, *, silent: bool = False) -> T: ...


# Compatibility type name; concrete adapters do not inherit it.
SecretRef = ISecretRef


@dataclass(frozen=True)
class DisclosureRequest:
    identifier: str


def safe_call[T](function: Callable[[], T]) -> T:
    error = SecurityError
    try:
        return function()
    except Exception as exc:  # noqa: BLE001 -- private callback/parser errors
        if type(exc) in _SAFE_ERRORS:
            error = type(exc)
    raise error()


def check_silent(silent: bool) -> None:
    if type(silent) is not bool:
        raise PermissionDenied()


@dataclass(frozen=True, repr=False)
class StoredSecret:
    _store: "SecretStore"
    identifier: str

    def ref(self, *, silent: bool = False) -> bytes:
        check_silent(silent)
        return self._store.reveal(self.identifier, silent=silent)

    def __repr__(self) -> str:
        return "StoredSecret(<private>)"

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        raise PermissionDenied()

    def __deepcopy__(self, memo: dict[int, Any]) -> Self:
        memo[id(self)] = self
        return self


class SecretStore:
    def __init__(
        self,
        vault: Vault,
        *,
        confirm: Callable[[DisclosureRequest], bool] | None = None,
    ):
        self._vault = vault
        self._confirm = confirm

    def __repr__(self) -> str:
        return "SecretStore(<private>)"

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        raise PermissionDenied()

    def capture(self, value: bytes) -> StoredSecret:
        def operation():
            if type(value) is not bytes or len(value) > MAX_SNAPSHOT_SIZE:
                raise InvalidStore()
            return StoredSecret(self, self._vault.save(value))

        return safe_call(operation)

    def capture_file(
        self, file: str | Path, *, legacy: LegacyContext | None = None
    ) -> StoredSecret:
        def operation():
            checkpoint = self._vault.checkpoint()
            path = Path(file).absolute()
            raw = snapshot_file(path).raw
            if raw.startswith(b"ENC1"):
                if legacy is None:
                    raise InteractionRequired()
                raw = legacy.decrypt_bytes(raw, source=path)
            with self._vault.mutex:
                if self._vault.checkpoint() != checkpoint:
                    raise PermissionDenied()
                return self.capture(raw)

        return safe_call(operation)

    def reference(self, identifier: str) -> StoredSecret:
        if (
            type(identifier) is not str
            or len(identifier) != 32
            or any(c not in "0123456789abcdef" for c in identifier)
        ):
            raise PermissionDenied()
        return StoredSecret(self, identifier)

    def reveal(self, identifier: str, *, silent: bool = False) -> bytes:
        def operation():
            check_silent(silent)
            checkpoint = self._vault.checkpoint()
            if not silent:
                if self._confirm is None:
                    raise InteractionRequired()
                if self._confirm(DisclosureRequest(identifier)) is not True:
                    raise PermissionDenied()
            with self._vault.mutex:
                if self._vault.checkpoint() != checkpoint:
                    raise PermissionDenied()
                raw = self._vault.read(identifier)
                if not raw:
                    return raw
                with LockedBuffer(
                    raw, protection=self._vault.protection, max_size=MAX_SNAPSHOT_SIZE
                ) as buffer:
                    value = buffer.copy_bytes()
                if self._vault.checkpoint() != checkpoint:
                    raise PermissionDenied()
                return value

        return safe_call(operation)


def __getattr__(name: str):
    # Preserve the former adapter import path without a concrete reference base.
    if name in {"SecretString", "SecretJson"}:
        from .adapters import SecretJson, SecretString

        return {"SecretString": SecretString, "SecretJson": SecretJson}[name]
    raise AttributeError(name)
