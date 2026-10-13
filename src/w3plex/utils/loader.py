import asyncio
import re
from collections.abc import Awaitable, Callable
from typing import Any, NotRequired, TypedDict, Unpack, overload

from w3ext import Account
from web3 import Web3

from ..security import SecretRef, SecretString
from .filter import TemplateFilter


class FileLoaderConfig(TypedDict):
    file: str
    filter: NotRequired[str]


class FileLoader[T]:
    def __init__(self, **config: Unpack[FileLoaderConfig]):
        self.config = config

    def __call__(self, *args, **kwargs):
        return self.process(*args, **kwargs)

    @overload
    async def process(self, fn: None = None) -> list[str]: ...
    @overload
    async def process(self, fn: Callable[[str], T]) -> list[T]: ...
    async def process(
        self, fn: Callable[[str], T] | None = None
    ) -> list[T] | list[str]:
        transform: Callable[[str], T | str] = fn or (lambda item: item)

        flt = (
            TemplateFilter(_f)
            if (_f := self.config.get("filter")) is not None
            else lambda **kwargs: True
        )

        def read_lines():
            with open(self.config["file"], "r", encoding="utf-8-sig") as fr:
                return list(fr)

        lines = await asyncio.to_thread(read_lines)
        return [
            val
            for line in lines
            if line.strip() and not line.lstrip().startswith("#")
            if flt(line=line)
            and (val := self.process_line(line.strip(), transform)) is not None
        ]

    def process_line(self, line: str, fn: Callable[[str], Any]) -> Any:
        return fn(line)

    @staticmethod
    def from_secret(
        source: SecretRef[bytes], *, filter: str | None = None
    ) -> "SecretFileLoader[Any]":
        """Opt in to reference results; the ordinary constructor stays compatible."""
        return SecretFileLoader(source, filter=filter)


class SecretFileLoader[T]:
    """Read UTF-8 lines as immutable ranges in an encrypted source snapshot."""

    def __init__(self, file: SecretRef[bytes], *, filter: str | None = None):
        self.file = file
        self._filter = TemplateFilter(filter) if filter is not None else None

    def __call__(self, *args, **kwargs):
        return self.process(*args, **kwargs)

    @overload
    async def process(self, fn: None = None) -> list[SecretString]: ...
    @overload
    async def process(self, fn: Callable[[SecretString], T]) -> list[T]: ...
    async def process(
        self, fn: Callable[[SecretString], T] | None = None
    ) -> list[T] | list[SecretString]:
        def read_lines(raw: bytes) -> list[SecretString]:
            result = []
            start = 3 if raw.startswith(b"\xef\xbb\xbf") else 0
            for match in re.finditer(rb"[^\r\n]*(?:\r\n|\r|\n|$)", raw[start:]):
                line = match[0].decode("utf-8")
                value = line.strip()
                if not value or line.lstrip().startswith("#"):
                    continue
                normalized = line.replace("\r\n", "\n").replace("\r", "\n")
                if self._filter is not None and not self._filter(line=normalized):
                    continue
                left = len(line) - len(line.lstrip())
                offset = start + match.start() + len(line[:left].encode("utf-8"))
                result.append(
                    SecretString(self.file, offset, len(value.encode("utf-8")))
                )
            return result

        lines = self.file._use(read_lines)
        if fn is None:
            return lines
        return [value for line in lines if (value := fn(line)) is not None]


def accounts_loader(
    **kwargs: Unpack[FileLoaderConfig],
) -> Callable[[], Awaitable[list[Account]]]:
    def wrapper():
        return FileLoader[Account](**kwargs).process(
            lambda item: Account.from_key(item)
        )

    return wrapper


async def wallets_loader(**kwargs: Unpack[FileLoaderConfig]) -> list[str]:
    """Load public EVM addresses, ignoring blank lines and comments."""

    def address(line: str) -> str:
        if not Web3.is_address(line):
            raise ValueError(f"Invalid wallet address in {kwargs['file']}: {line}")
        return Web3.to_checksum_address(line)

    return await FileLoader[str](**kwargs).process(address)
