"""Runner-owned reads of ordinary files and immutable encrypted sources."""

import io
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Never, Self, SupportsIndex

from . import file_format
from .diagnostics import private_call
from .encrypted_io import EncryptedIOContext, detect_format
from .errors import InteractionRequired, PermissionDenied
from .io import create_context
from .snapshots import snapshot_file


@dataclass(frozen=True, repr=False)
class PlainFile:
    """Ordinary file bytes, to be decoded without keeping a protected reference."""

    data: bytes


@dataclass(frozen=True, repr=False)
class _EncryptedFileRef:
    context: EncryptedIOContext
    ciphertext: bytes
    source: Path
    generation: int

    def ref(self, *, silent: bool = False) -> bytes:
        def operation():
            if type(silent) is not bool or self.context.generation != self.generation:
                raise PermissionDenied()
            if not silent:
                # Standalone capture has no disclosure-confirmation handler.
                raise InteractionRequired()
            value = self.context.decrypt_bytes(
                self.ciphertext, source=self.source, ask_password=False
            )
            if self.context.generation != self.generation:
                raise PermissionDenied()
            return value

        return private_call(operation)

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        raise PermissionDenied()

    def __deepcopy__(self, memo: dict[int, Any]) -> Self:
        memo[id(self)] = self
        return self


class DefaultFileOpener:
    """Read plain files normally and capture ciphertext using an owned context.

    Password input and the selected standalone keystore are used only when an
    encrypted source is first captured. Closing this opener invalidates its
    references without changing builtins.open or another runner's context.
    """

    def __init__(self):
        self._context: EncryptedIOContext | None = None
        self._mutex = threading.Lock()
        self._closed = False

    def __call__(self, file: str | Path) -> PlainFile | _EncryptedFileRef:
        def operation():
            with self._mutex:
                if self._closed:
                    raise PermissionDenied()
            path = Path(file).absolute()
            with io.open(path, "rb") as stream:  # noqa: UP020 -- inspect ciphertext without global decryption
                prefix = stream.read(8)
                if detect_format(prefix) == "plain":
                    result = PlainFile(prefix + stream.read())
                    with self._mutex:
                        if self._closed:
                            raise PermissionDenied()
                    return result

            raw = snapshot_file(path, maximum_size=file_format.MAXIMUM_SIZE).raw
            if detect_format(raw) == "plain":
                raise PermissionDenied()
            with self._mutex:
                if self._closed:
                    raise PermissionDenied()
                if self._context is None:
                    self._context = create_context()
                context = self._context
            generation = context.generation
            # Authenticate in the capture worker, including any terminal input.
            # The reference retains only ciphertext; the context caches its key.
            context.decrypt_bytes(raw, source=path)
            if context.generation != generation:
                raise PermissionDenied()
            return _EncryptedFileRef(context, raw, path, generation)

        return private_call(operation)

    def close(self) -> None:
        """Close this opener's context even when a capture is awaiting input."""
        with self._mutex:
            self._closed = True
            context = self._context
        if context is not None:
            context.close()
