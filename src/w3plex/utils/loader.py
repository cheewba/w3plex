import asyncio
import inspect
import io
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
from ..security.diagnostics import private_async, private_call
from ..security.errors import PermissionDenied
from ..security.file_opener import PlainFile
from ..w3.account import Account as ReferenceAccount
from .filter import TemplateFilter

type FileOpener = Callable[
    [str | Path],
    ISecretRef[bytes] | PlainFile | Awaitable[ISecretRef[bytes] | PlainFile],
]

_FILE_OPENER: ContextVar[FileOpener | None] = ContextVar(
    "w3plex_file_opener", default=None
)


def get_file_opener() -> FileOpener | None:
    """Get the file opener set in the current context.

    Returns:
        The opener callback, or None if no opener is set.
    """
    return _FILE_OPENER.get()


@contextmanager
def using_file_opener(opener: FileOpener | None) -> Iterator[None]:
    """Set the opener for readers created inside a with block.

    Args:
        opener: A sync or async callback returning a byte reference, or PlainFile for
            ordinary uncached reads. None disables capture in this scope.

    Returns:
        A context manager that restores the previous opener on exit.
    """
    token = _FILE_OPENER.set(opener)
    try:
        yield
    finally:
        _FILE_OPENER.reset(token)


class FileLoaderConfig(TypedDict):
    file: str | Path | ISecretRef[bytes]
    filter: NotRequired[str]


class FileLoader[T]:
    """Read selected lines using the opener set when this reader was created."""

    def __init__(self, **config: Unpack[FileLoaderConfig]):
        """Keep the reader options and the current file opener.

        Args:
            **config: Reader options: file is a path or byte reference. filter is an
                optional regular expression; * selects all lines.

        Returns:
            None.
        """
        self.config = config
        self._opener = get_file_opener()
        self._source: ISecretRef[bytes] | None = None

        if self._opener is not None:
            self._source_lock = threading.Lock()
            self._async_source_lock = asyncio.Lock()

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
        """Read selected lines and optionally apply a function to each.

        Ordinary reads return strings. Protected captures return SecretString
        references. A successful protected capture is reused on later calls.

        Args:
            fn: Optional function called with each str or SecretString value. Results
                equal to None are skipped.

        Returns:
            Selected line values, or the results returned by fn.
        """
        transform: Callable[[Any], Any] = fn or (lambda item: item)

        flt = (
            TemplateFilter(_f)
            if (_f := self.config.get("filter")) is not None
            else lambda **kwargs: True
        )

        file = self.config["file"]
        source: ISecretRef[bytes] | None = None
        lines: list[str] = []
        if isinstance(file, ISecretRef):
            source = file
        elif self._opener is not None:
            captured = await self._capture(file, self._opener)
            if isinstance(captured, PlainFile):
                with io.TextIOWrapper(
                    io.BytesIO(captured.data), encoding="utf-8-sig"
                ) as stream:
                    lines = list(stream)
            else:
                source = captured
        else:

            def read_lines():
                with open(file, "r", encoding="utf-8-sig") as fr:
                    return list(fr)

            lines = await asyncio.to_thread(read_lines)
        if source is None:
            return [
                val
                for line in lines
                if line.strip() and not line.lstrip().startswith("#")
                if flt(line=line)
                and (val := self.process_line(line.strip(), transform)) is not None
            ]

        references = private_call(
            lambda: self._reference_lines(source, source.ref(silent=True), flt)
        )
        return private_call(
            lambda: [
                value
                for line in references
                if (value := self.process_line(line, transform)) is not None
            ]
        )

    def process_line(self, line: str | SecretString, fn: Callable[[Any], Any]) -> Any:
        """Apply the line function; subclasses can override this method.

        Args:
            line: A selected text line or a reference to it.
            fn: Function used to turn the line into a result.

        Returns:
            The result of fn(line). None tells the loader to skip this line.
        """
        return fn(line)

    @private_async
    async def _capture(
        self, file: str | Path, opener: FileOpener
    ) -> ISecretRef[bytes] | PlainFile:
        """Capture a file once and reuse the saved reference.

        Args:
            file: Path of the file to capture.
            opener: Sync or async callback returning a byte reference.

        Returns:
            The source reference or uncached ordinary bytes. Async work runs in the
            task that called this method.
        """
        async with self._async_source_lock:
            if self._source is None:
                # The host may require password input to run in the calling task.
                if inspect.iscoroutinefunction(opener) or inspect.iscoroutinefunction(
                    opener.__call__
                ):
                    source = opener(file)
                else:
                    capture = asyncio.create_task(
                        asyncio.to_thread(self._capture_sync, file, opener)
                    )

                    try:
                        # Let the worker finish even if the reader is cancelled.
                        source = await asyncio.shield(capture)
                    except asyncio.CancelledError:
                        capture.add_done_callback(self._discard_capture)
                        raise

                # A normal function can also return an awaitable.
                if inspect.isawaitable(source):
                    source = await source

                if isinstance(source, PlainFile):
                    return source
                if not isinstance(source, ISecretRef):
                    raise PermissionDenied()

                self._source = source

            return self._source

    @staticmethod
    def _discard_capture(capture: asyncio.Task) -> None:
        """Close a coroutine that a cancelled reader can no longer await.

        Args:
            capture: Worker task whose result is no longer awaited by the reader.

        Returns:
            None.
        """
        try:
            source = capture.result()
        except (asyncio.CancelledError, Exception):  # noqa: BLE001 -- cancelled reader has no recipient for worker errors
            return

        if inspect.iscoroutine(source):
            source.close()

    def _capture_sync(
        self, file: str | Path, opener: FileOpener
    ) -> ISecretRef[bytes] | PlainFile | Awaitable[ISecretRef[bytes] | PlainFile]:
        """Call a sync opener in a worker thread.

        Args:
            file: Path of the file to capture.
            opener: Callback returning a reference or an awaitable.

        Returns:
            The cached reference or the result of opener(file). A ready reference is
            saved before the worker returns.
        """
        with self._source_lock:
            if self._source is not None:
                return self._source

            source = private_call(lambda: opener(file))
            if isinstance(source, ISecretRef):
                # Keep the result even if the reader stops waiting for this worker.
                self._source = source
            elif not isinstance(source, PlainFile) and not inspect.isawaitable(source):
                raise PermissionDenied()

            return source

    @staticmethod
    def _reference_lines(
        source: ISecretRef[bytes], raw: bytes, flt: Callable[..., bool]
    ) -> list[SecretString]:
        """Find line ranges in the original UTF-8 source bytes.

        Args:
            source: The parent reference used by each returned line.
            raw: Source bytes, possibly starting with a UTF-8 BOM.
            flt: Filter called with line=normalized_text for each non-comment line.

        Returns:
            SecretString references for the selected lines.
        """
        result = []
        start = 3 if raw.startswith(b"\xef\xbb\xbf") else 0
        for match in re.finditer(rb"[^\r\n]*(?:\r\n|\r|\n|$)", raw[start:]):
            line = match[0].decode("utf-8")
            value = line.strip()
            if not value or line.lstrip().startswith("#"):
                continue

            # Filters see normalized newlines; reference offsets use original bytes.
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
    """Create a function that loads accounts when called.

    Args:
        **kwargs: Reader options: file is a path or byte reference. filter is an
            optional regular expression; * selects all lines.

    Returns:
        A function whose result can be awaited to get the selected accounts.
    """
    reader = FileLoader[Account](**kwargs)

    def account(line: str | SecretString) -> Account:
        if isinstance(line, ISecretRef):
            return ReferenceAccount.from_key(line)
        return Account.from_key(line)

    def wrapper():
        return reader.process(account)

    return wrapper


async def wallets_loader(**kwargs: Unpack[FileLoaderConfig]) -> list[str]:
    """Load public EVM addresses, skipping blank lines and comments.

    Args:
        **kwargs: Reader options: file is a path or byte reference. filter is an
            optional regular expression; * selects all lines.

    Returns:
        Selected addresses in checksum format.
    """

    def address(line: str | SecretString) -> str:
        if isinstance(line, ISecretRef):
            return private_call(lambda: address(line.ref(silent=True)))
        if not Web3.is_address(line):
            raise ValueError(f"Invalid wallet address in {kwargs['file']}: {line}")
        return Web3.to_checksum_address(line)

    return await FileLoader[str](**kwargs).process(address)
