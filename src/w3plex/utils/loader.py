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

from ..security import ISecretRef, SecretString
from ..security.errors import PermissionDenied
from ..security.refs import safe_call
from .filter import TemplateFilter

type FileOpener = Callable[[str | Path], ISecretRef[bytes]]

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
    file: str | Path | ISecretRef[bytes]
    filter: NotRequired[str]
    opener: NotRequired[FileOpener]


class FileLoader[T]:
    def __init__(self, **config: Unpack[FileLoaderConfig]):
        self.config = config
        self._opener = config.get("opener", _FILE_OPENER.get())
        self._source: ISecretRef[bytes] | None = None
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
        if isinstance(file, ISecretRef) or self._opener is not None:
            source = await asyncio.to_thread(self._capture)
            lines = safe_call(
                lambda: self._reference_lines(source, source.ref(silent=True), flt)
            )
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

    def _capture(self) -> ISecretRef[bytes]:
        file = self.config["file"]
        if isinstance(file, ISecretRef):
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
                if not isinstance(source, ISecretRef):
                    raise PermissionDenied()
                self._source = source
            return self._source

    @staticmethod
    def _reference_lines(
        source: ISecretRef[bytes], raw: bytes, flt: Callable[..., bool]
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


def accounts_loader(
    **kwargs: Unpack[FileLoaderConfig],
) -> Callable[[], Awaitable[list[Account]]]:
    reader = FileLoader[Account](**kwargs)

    def account(line: str | SecretString) -> Account:
        if isinstance(line, ISecretRef):
            from ..w3.account import Account as ReferenceAccount

            return ReferenceAccount.from_key(line)
        return Account.from_key(line)

    def wrapper():
        return reader.process(account)

    return wrapper


async def wallets_loader(**kwargs: Unpack[FileLoaderConfig]) -> list[str]:
    """Load public EVM addresses, ignoring blank lines and comments."""

    def address(line: str | SecretString) -> str:
        if isinstance(line, ISecretRef):
            return safe_call(lambda: address(line.ref(silent=True)))
        if not Web3.is_address(line):
            raise ValueError(f"Invalid wallet address in {kwargs['file']}: {line}")
        return Web3.to_checksum_address(line)

    return await FileLoader[str](**kwargs).process(address)
