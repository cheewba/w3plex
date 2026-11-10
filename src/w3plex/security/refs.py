"""References to encrypted values that cannot change after saving."""

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import (
    Any,
    Never,
    Protocol,
    Self,
    SupportsIndex,
    runtime_checkable,
)

from . import file_format
from .diagnostics import private_call
from .encrypted_io import EncryptedIOContext, detect_format
from .errors import InteractionRequired, InvalidStore, PermissionDenied
from .legacy import LegacyContext
from .snapshots import snapshot_file
from .vault import Vault

MAX_SNAPSHOT_SIZE = 1024 * 1024


@runtime_checkable
class ISecretRef[T](Protocol):
    """Describe how to read a value through a reference."""

    def ref(self, *, silent: bool = False) -> T:
        """Read the current value through a reference.

        Args:
            silent: If True, skip the confirmation prompt. This does not grant
                permission to read the value.

        Returns:
            The referenced value.
        """
        ...


@dataclass(frozen=True)
class DisclosureRequest:
    """Identify the record that a caller wants to show.

    Args:
        identifier: ID of the record whose value needs confirmation.
    """

    identifier: str


@dataclass(frozen=True, repr=False)
class StoredSecret:
    """A local reference to a saved record whose value cannot change.

    Args:
        _store: Store that manages the record.
        identifier: ID of the saved record.
    """

    _store: "SecretStore"
    identifier: str

    def ref(self, *, silent: bool = False) -> bytes:
        """Read the saved value through its store.

        Args:
            silent: If True, skip the confirmation prompt. This does not grant
                permission to read the value.

        Returns:
            The saved bytes.
        """
        return self._store.reveal(self.identifier, silent=silent)

    def __repr__(self) -> str:
        return "StoredSecret(<private>)"

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        raise PermissionDenied()

    def __deepcopy__(self, memo: dict[int, Any]) -> Self:
        memo[id(self)] = self
        return self


class SecretStore:
    """Save byte values that cannot be changed after saving."""

    def __init__(
        self,
        vault: Vault,
        *,
        confirm: Callable[[DisclosureRequest], bool] | None = None,
    ):
        """Use a vault to save values and confirm requests to show them.

        Args:
            vault: The vault that stores values. The caller manages its lifetime.
            confirm: Optional callback taking a DisclosureRequest. It must return True
                to show a value.

        Returns:
            None.
        """
        self._vault = vault
        self._confirm = confirm

    def __repr__(self) -> str:
        return "SecretStore(<private>)"

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        raise PermissionDenied()

    def capture(self, value: bytes) -> StoredSecret:
        """Save bytes as a value that cannot change later.

        Args:
            value: Bytes to save. A value can contain up to 1 MiB.

        Returns:
            A StoredSecret reference to the saved value.
        """

        def operation():
            if type(value) is not bytes or len(value) > MAX_SNAPSHOT_SIZE:
                raise InvalidStore()
            return StoredSecret(self, self._vault.save(value))

        return private_call(operation)

    def capture_file(
        self,
        file: str | Path,
        *,
        context: EncryptedIOContext | LegacyContext | None = None,
    ) -> StoredSecret:
        """Save a stable copy of a file in the vault.

        The vault must remain in the same unlocked session while the file is read and
        any password is entered.

        Args:
            file: Path of the source file. The original file is not changed.
            context: Context used to decrypt an encrypted source. None supports plain
                files only.

        Returns:
            A StoredSecret reference to the saved bytes.
        """

        def operation():
            checkpoint = self._vault.checkpoint()

            path = Path(file).absolute()
            raw = snapshot_file(path).raw
            kind = detect_format(raw)
            if (
                kind == "modern"
                and len(file_format.parse(raw).payload) > MAX_SNAPSHOT_SIZE + 16
            ):
                raise InvalidStore()
            if kind != "plain":
                if context is None or (
                    kind == "modern" and not isinstance(context, EncryptedIOContext)
                ):
                    raise InteractionRequired()
                raw = context.decrypt_bytes(raw, source=path)

            # The vault may have been locked and reopened while asking for a password.
            with self._vault.mutex:
                if self._vault.checkpoint() != checkpoint:
                    raise PermissionDenied()
                return self.capture(raw)

        return private_call(operation)

    def reference(self, identifier: str) -> StoredSecret:
        """Create a local reference without reading its value.

        Args:
            identifier: The 32-character record ID.

        Returns:
            A StoredSecret handle. The record is checked when the handle is read.
        """
        if (
            type(identifier) is not str
            or len(identifier) != 32
            or any(c not in "0123456789abcdef" for c in identifier)
        ):
            raise PermissionDenied()
        return StoredSecret(self, identifier)

    def reveal(self, identifier: str, *, silent: bool = False) -> bytes:
        """Read a saved value, asking for confirmation when needed.

        Args:
            identifier: ID of the record to read.
            silent: If True, skip the confirmation prompt. This does not grant
                permission to read the value.

        Returns:
            The saved bytes from the unlocked vault.
        """

        def operation():
            if type(silent) is not bool:
                raise PermissionDenied()

            checkpoint = self._vault.checkpoint()
            if not silent:
                if self._confirm is None:
                    raise InteractionRequired()
                if self._confirm(DisclosureRequest(identifier)) is not True:
                    raise PermissionDenied()

            # Confirmation applies only to the session in which it was requested.
            with self._vault.mutex:
                if self._vault.checkpoint() != checkpoint:
                    raise PermissionDenied()
                value = self._vault.read(identifier)
                if self._vault.checkpoint() != checkpoint:
                    raise PermissionDenied()
                return value

        return private_call(operation)
