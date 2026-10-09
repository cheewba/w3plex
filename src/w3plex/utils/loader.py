import asyncio
from collections.abc import Awaitable, Callable
from typing import Any, NotRequired, TypedDict, Unpack, overload

from w3ext import Account
from web3 import Web3

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
