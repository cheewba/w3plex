"""Text and JSON references that store a path or range, not parsed values."""

import json
from dataclasses import dataclass
from typing import Any, Never, Self, SupportsIndex, cast

from .diagnostics import private_call
from .errors import InvalidStore, PermissionDenied
from .refs import ISecretRef
from .vault_format import reject_json_constant, unique_fields


@dataclass(frozen=True, repr=False)
class SecretString:
    """Read a text part from a parent reference when requested.

    Args:
        parent: Reference to source bytes or text.
        offset: Start position in the encoded bytes, not in text characters.
        length: Number of bytes to read. None reads to the end of the value.
        encoding: Encoding used to convert between text and bytes.
    """

    parent: ISecretRef[bytes | str]
    offset: int = 0
    length: int | None = None
    encoding: str = "utf-8"

    def __post_init__(self):
        if self.offset < 0 or (self.length is not None and self.length < 0):
            raise InvalidStore()

    def ref(self, *, silent: bool = False) -> str:
        """Read the parent value and decode the selected byte range.

        Args:
            silent: If True, skip the confirmation prompt. This does not grant
                permission to read the value.

        Returns:
            The selected text.
        """

        def operation():
            value = self.parent.ref(silent=silent)
            if isinstance(value, str):
                value = value.encode(self.encoding)

            end = len(value) if self.length is None else self.offset + self.length
            if not 0 <= self.offset <= end <= len(value):
                raise InvalidStore()

            return value[self.offset : end].decode(self.encoding)

        return private_call(operation)

    def __repr__(self) -> str:
        return "SecretString(<private>)"

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        raise PermissionDenied()

    def __deepcopy__(self, memo: dict[int, Any]) -> Self:
        memo[id(self)] = self
        return self


@dataclass(frozen=True, repr=False)
class SecretJson[T]:
    """Read a JSON value without keeping the parsed data.

    Args:
        parent: Reference to JSON bytes, JSON text or an already selected JSON value.
        path: Dictionary keys and list indexes to follow. An empty path returns the
            whole value.
    """

    parent: ISecretRef
    path: tuple[str | int, ...] = ()

    def __post_init__(self):
        object.__setattr__(self, "path", tuple(self.path))

    def __getitem__(self, key: str | int) -> "SecretJson[Any]":
        return SecretJson(self, (key,))

    def ref(self, *, silent: bool = False) -> T:
        """Read the parent value and follow the JSON path.

        Args:
            silent: If True, skip the confirmation prompt. This does not grant
                permission to read the value.

        Returns:
            The JSON value at the selected path.
        """

        def operation():
            value = self.parent.ref(silent=silent)
            if type(value) in {str, bytes}:
                value = json.loads(
                    value,
                    object_pairs_hook=unique_fields,
                    parse_constant=reject_json_constant,
                )

            for key in self.path:
                if not isinstance(value, (dict, list)):
                    raise InvalidStore()
                value = cast(Any, value)[key]

            return cast(T, value)

        return private_call(operation)

    def __repr__(self) -> str:
        return "SecretJson(<private>)"

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        raise PermissionDenied()

    def __deepcopy__(self, memo: dict[int, Any]) -> Self:
        memo[id(self)] = self
        return self
