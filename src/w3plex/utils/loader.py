import asyncio
import re
import threading
from collections.abc import Awaitable, Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Any, NotRequired, TypedDict, Unpack, overload

from w3ext import Account
from web3 import Web3

from ..security import SecretRef, SecretString
from ..security.errors import PermissionDenied
from ..security.refs import safe_call
from .filter import TemplateFilter

type FileOpener = Callable[[str | Path], SecretRef[bytes]]

_FILE_OPENER: ContextVar[FileOpener | None] = ContextVar(
    "w3plex_file_opener", default=None
)


def get_file_opener() -> FileOpener | None:
    return _FILE_OPENER.get()


@contextmanager
def using_file_opener(opener: FileOpener | None) -> Iterator[None]:
    token = _FILE_OPENER.set(opener)
    try:
        yield
    finally:
        _FILE_OPENER.reset(token)


class FileLoaderConfig(TypedDict):
    file: str | Path | SecretRef[bytes]
    filter: NotRequired[str]
    opener: NotRequired[FileOpener]


class FileLoader[T]:
    def __init__(self, **config: Unpack[FileLoaderConfig]):
        self.config = config
        self._opener = config.get("opener", _FILE_OPENER.get())
        self._source: SecretRef[bytes] | None = None
        self._source_lock = threading.Lock() if self._opener is not None else None

    def __call__(self, *args, **kwargs):
        return self.process(*args, **kwargs)

    @overload
    async def process(self, fn: None = None) -> list[str] | list[SecretString]: ...
    @overload
    async def process(
        self, fn: Callable[[str], T] | Callable[[SecretString], T]
    ) -> list[T]: ...
    async def process(
        self, fn: Callable[[str], T] | Callable[[SecretString], T] | None = None
    ) -> list[T] | list[str] | list[SecretString]:
        transform: Callable[[Any], Any] = fn or (lambda item: item)

        flt = (
            TemplateFilter(_f)
            if (_f := self.config.get("filter")) is not None
            else lambda **kwargs: True
        )

        file = self.config["file"]
        if isinstance(file, SecretRef) or self._opener is not None:
            source = await asyncio.to_thread(self._capture)
            lines = source._use(lambda raw: self._reference_lines(source, raw, flt))
            return safe_call(
                lambda: [
                    value
                    for line in lines
                    if (value := self.process_line(line, transform)) is not None
                ]
            )

        def read_lines():
            with open(file, "r", encoding="utf-8-sig") as fr:
                return list(fr)

        lines = await asyncio.to_thread(read_lines)
        return [
            val
            for line in lines
            if line.strip() and not line.lstrip().startswith("#")
            if flt(line=line)
            and (val := self.process_line(line.strip(), transform)) is not None
        ]

    def process_line(self, line: str | SecretString, fn: Callable[[Any], Any]) -> Any:
        return fn(line)

    def _capture(self) -> SecretRef[bytes]:
        file = self.config["file"]
        if isinstance(file, SecretRef):
            return file
        lock = self._source_lock
        if lock is None:
            raise PermissionDenied()
        with lock:
            if self._source is None:
                opener = self._opener
                if opener is None:
                    raise PermissionDenied()
                source = safe_call(lambda: opener(file))
                if not isinstance(source, SecretRef):
                    raise PermissionDenied()
                self._source = source
            return self._source

    @staticmethod
    def _reference_lines(
        source: SecretRef[bytes], raw: bytes, flt: Callable[..., bool]
    ) -> list[SecretString]:
        result = []
        start = 3 if raw.startswith(b"\xef\xbb\xbf") else 0
        for match in re.finditer(rb"[^\r\n]*(?:\r\n|\r|\n|$)", raw[start:]):
            line = match[0].decode("utf-8")
            value = line.strip()
            if not value or line.lstrip().startswith("#"):
                continue
            normalized = line.replace("\r\n", "\n").replace("\r", "\n")
            if not flt(line=normalized):
                continue
            left = len(line) - len(line.lstrip())
            offset = start + match.start() + len(line[:left].encode("utf-8"))
            result.append(SecretString(source, offset, len(value.encode("utf-8"))))
        return result

    @staticmethod
    def from_secret(
        source: SecretRef[bytes], *, filter: str | None = None
    ) -> "SecretFileLoader[Any]":
        """Opt in to reference results; the ordinary constructor stays compatible."""
        return SecretFileLoader(source, filter=filter)


class SecretFileLoader[T](FileLoader[T]):
    """Compatibility constructor for the reference path of FileLoader."""

    def __init__(self, file: SecretRef[bytes], *, filter: str | None = None):
        self.file = file
        config: FileLoaderConfig = {"file": file}
        if filter is not None:
            config["filter"] = filter
        super().__init__(**config)


def accounts_loader(
    **kwargs: Unpack[FileLoaderConfig],
) -> Callable[[], Awaitable[list[Account]]]:
    reader = FileLoader[Account](**kwargs)

    def account(line: str | SecretString) -> Account:
        if isinstance(line, SecretRef):
            from ..w3.account import Account as ReferenceAccount

            return ReferenceAccount.from_key(line)
        return Account.from_key(line)

    def wrapper():
        return reader.process(account)

    return wrapper


async def wallets_loader(**kwargs: Unpack[FileLoaderConfig]) -> list[str]:
    """Load public EVM addresses, ignoring blank lines and comments."""

    def address(line: str | SecretString) -> str:
        if isinstance(line, SecretRef):
            return line._use(address)
        if not Web3.is_address(line):
            raise ValueError(f"Invalid wallet address in {kwargs['file']}: {line}")
        return Web3.to_checksum_address(line)

    return await FileLoader[str](**kwargs).process(address)
