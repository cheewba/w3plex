"""Text and JSON references retain extraction metadata, never decoded values."""

import json
from dataclasses import dataclass
from typing import Any, Never, Self, SupportsIndex, cast

from .errors import InvalidStore, PermissionDenied
from .refs import ISecretRef, check_silent, safe_call
from .vault_format import reject_json_constant, unique_fields


def validate_parent(parent: ISecretRef) -> None:
    if not isinstance(parent, ISecretRef):
        raise InvalidStore()
    depth = 0
    while isinstance(parent, (SecretString, SecretJson)):
        depth += 1
        if depth >= 32:
            raise InvalidStore()
        parent = parent.parent


@dataclass(frozen=True, repr=False)
class SecretString:
    parent: ISecretRef[bytes | str]
    offset: int = 0
    length: int | None = None
    encoding: str = "utf-8"

    def __post_init__(self):
        validate_parent(self.parent)
        if (
            type(self.offset) is not int
            or self.offset < 0
            or (
                self.length is not None
                and (type(self.length) is not int or self.length < 0)
            )
            or type(self.encoding) is not str
            or not 1 <= len(self.encoding) <= 64
        ):
            raise InvalidStore()

    def ref(self, *, silent: bool = False) -> str:
        check_silent(silent)

        def operation():
            value = self.parent.ref(silent=silent)
            if type(value) is str:
                value = value.encode(self.encoding)
            if type(value) is not bytes:
                raise InvalidStore()
            end = len(value) if self.length is None else self.offset + self.length
            if not self.offset <= end <= len(value):
                raise InvalidStore()
            return value[self.offset : end].decode(self.encoding)

        return safe_call(operation)

    def __repr__(self) -> str:
        return "SecretString(<private>)"

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        raise PermissionDenied()

    def __deepcopy__(self, memo: dict[int, Any]) -> Self:
        memo[id(self)] = self
        return self


@dataclass(frozen=True, repr=False)
class SecretJson[T]:
    parent: ISecretRef
    path: tuple[str | int, ...] = ()

    def __post_init__(self):
        validate_parent(self.parent)
        object.__setattr__(self, "path", tuple(self.path))
        if len(self.path) > 32 or any(
            not (type(key) is str or (type(key) is int and key >= 0))
            for key in self.path
        ):
            raise InvalidStore()

    def __getitem__(self, key: str | int) -> "SecretJson[Any]":
        return SecretJson(self, (key,))

    def ref(self, *, silent: bool = False) -> T:
        check_silent(silent)

        def operation():
            value = self.parent.ref(silent=silent)
            if type(value) in {str, bytes}:
                value = json.loads(
                    value,
                    object_pairs_hook=unique_fields,
                    parse_constant=reject_json_constant,
                )
            for key in self.path:
                if (
                    type(key) is str
                    and type(value) is dict
                    or type(key) is int
                    and type(value) is list
                ):
                    value = cast(Any, value)[key]
                else:
                    raise InvalidStore()
            return cast(T, value)

        return safe_call(operation)

    def __repr__(self) -> str:
        return "SecretJson(<private>)"

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        raise PermissionDenied()

    def __deepcopy__(self, memo: dict[int, Any]) -> Self:
        memo[id(self)] = self
        return self
