"""Explicit nonsecret snapshot exports; decrypting never grants export rights."""

import asyncio
import hashlib
import os
import secrets
import stat
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Protocol

from ..security.contracts import Public
from ..security.diagnostics import private_async
from ..security.errors import PermissionDenied, UnsupportedProtection
from ..security.interaction import PrivateInput
from ..security.legacy import LegacyContext
from ..security.session import Session
from ..security.storage import CiphertextFile


class FileClassification(StrEnum):
    NONSECRET = "nonsecret"
    SECRET = "secret"
    UNCLASSIFIED = "unclassified"


@dataclass(frozen=True)
class FileRef:
    identifier: Annotated[str, Public]


@dataclass(frozen=True)
class ExportRequest:
    operation: Annotated[str, Public]
    source: Annotated[FileRef, Public]
    ciphertext_digest: Annotated[str, Public]
    size: Annotated[int, Public]


class ExportAuthorizer(Protocol):
    async def authorize(self, request: ExportRequest) -> bool: ...


@dataclass(frozen=True, repr=False)
class _Snapshot:
    identity: tuple[int, int, int, int, int]
    raw: bytes


def _snapshot_file(path: Path) -> _Snapshot:
    parent = CiphertextFile._open_directory(path.parent)
    directory = os.fstat(parent)
    fd = None
    try:
        fd = os.open(
            path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent
        )
        first = os.fstat(fd)
        if (
            not stat.S_ISREG(first.st_mode)
            or first.st_nlink != 1
            or first.st_size > 64 * 1024 * 1024
        ):
            raise PermissionDenied()
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(64 * 1024 * 1024 + 1)
        last = os.fstat(fd)
        named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)

        def identity(value):
            return (
                value.st_dev,
                value.st_ino,
                value.st_size,
                value.st_mtime_ns,
                value.st_ctime_ns,
            )

        if (
            last.st_nlink != 1
            or named.st_nlink != 1
            or len(raw) > 64 * 1024 * 1024
            or identity(first) != identity(last)
            or identity(last) != identity(named)
        ):
            raise PermissionDenied()
        current = CiphertextFile._open_directory(path.parent)
        try:
            selected = os.fstat(current)
            if (directory.st_dev, directory.st_ino) != (
                selected.st_dev,
                selected.st_ino,
            ):
                raise PermissionDenied()
        finally:
            os.close(current)
        return _Snapshot(identity(last), raw)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


class FileExports:
    """Host-owned registry confined to the approved work/snapshot directory.

    The host separately supplies every protected path. Agent RPC binds only the
    ``read`` method, never ``register`` or the decryptor. External input first
    needs the application's separately approved snapshot into this directory.
    """

    def __init__(
        self,
        work_root: Path,
        *,
        protected_paths: tuple[Path, ...],
        legacy: LegacyContext,
        private_input: PrivateInput,
        authorizer: ExportAuthorizer | None,
        session: Session | None = None,
    ):
        if os.name != "posix":
            raise UnsupportedProtection()
        self._root = Path(os.path.abspath(work_root))
        fd = CiphertextFile._open_directory(self._root)
        try:
            info = os.fstat(fd)
            self._root_identity = (info.st_dev, info.st_ino)
        finally:
            os.close(fd)
        self._protected = tuple(Path(os.path.abspath(path)) for path in protected_paths)
        self._legacy, self._input, self._authorizer = legacy, private_input, authorizer
        self._session = session
        self._sources: dict[str, tuple[Path, FileClassification]] = {}

    async def _lock_context(self) -> None:
        self._legacy.lock()

    def register(
        self,
        path: Path,
        *,
        classification: FileClassification = FileClassification.UNCLASSIFIED,
    ) -> FileRef:
        """Trusted control registration only. A model cannot classify a source."""
        if not isinstance(classification, FileClassification):
            raise PermissionDenied()
        normalized = Path(os.path.abspath(path))
        if not normalized.is_relative_to(self._root):
            raise PermissionDenied()
        reference = FileRef(secrets.token_hex(16))
        self._sources[reference.identifier] = (normalized, classification)
        return reference

    def _check(self, path: Path):
        root_fd = CiphertextFile._open_directory(self._root)
        try:
            info = os.fstat(root_fd)
            if (info.st_dev, info.st_ino) != self._root_identity:
                raise PermissionDenied()
        finally:
            os.close(root_fd)
        if any(
            path == protected or path.is_relative_to(protected)
            for protected in self._protected
        ):
            raise PermissionDenied()

    def _snapshot(self, path: Path) -> _Snapshot:
        self._check(path)
        snapshot = _snapshot_file(path)
        self._check(path)
        return snapshot

    @private_async
    async def read(self, reference: FileRef, *, operation: str) -> bytes:
        selected = self._sources.get(reference.identifier)
        if (
            selected is None
            or selected[1] is not FileClassification.NONSECRET
            or not operation
            or self._authorizer is None
        ):
            raise PermissionDenied()
        path = selected[0]
        snapshot = self._snapshot(path)
        request = ExportRequest(
            operation,
            reference,
            hashlib.sha256(snapshot.raw).hexdigest(),
            len(snapshot.raw),
        )
        if await self._authorizer.authorize(request) is not True:
            raise PermissionDenied()
        # Refuse a changed source before prompting, then again before export.
        if self._snapshot(path) != snapshot:
            raise PermissionDenied()
        generation = None
        if snapshot.raw.startswith(b"ENC1"):
            if self._session is None:
                raise PermissionDenied()
            generation = self._session.status().generation
            task = asyncio.current_task()
            if task is None:
                raise PermissionDenied()
            # Keep the cache closer registered between reads until session lock.
            self._session.track(generation, task, close=self._lock_context)
        plaintext = await self._legacy.decrypt_private(
            snapshot.raw,
            source=path,
            private_input=self._input,
            operation=operation,
            session=self._session if generation is not None else None,
            generation=generation,
        )
        if self._snapshot(path) != snapshot:
            raise PermissionDenied()
        return plaintext
