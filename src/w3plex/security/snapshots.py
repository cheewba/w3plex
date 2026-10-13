"""Bounded stable source reads; callers keep plaintext snapshots private."""

import os
import stat
from dataclasses import dataclass
from pathlib import Path

from .errors import PermissionDenied
from .storage import CiphertextFile


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
