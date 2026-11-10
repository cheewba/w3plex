"""Read source files with size limits and check for changes."""

import os
import stat
from dataclasses import dataclass
from pathlib import Path

from .errors import PermissionDenied
from .storage import CiphertextFile


@dataclass(frozen=True, repr=False)
class FileSnapshot:
    """Keep the file bytes and the details checked during the read.

    Args:
        identity: Device, inode, size, modification time and metadata change time, in
            that order. Times are in nanoseconds.
        raw: Bytes read from the source file. They may be plain or encrypted.
    """

    identity: tuple[int, int, int, int, int]
    raw: bytes


def snapshot_file(path: Path, *, maximum_size: int = 64 * 1024 * 1024) -> FileSnapshot:
    """Read a file and check that it does not change during the read.

    Args:
        path: Absolute path to a regular file. Links are not followed.
        maximum_size: Largest file allowed, in bytes.

    Returns:
        A FileSnapshot containing the bytes and checked file identity.
    """
    if type(maximum_size) is not int or not 1 <= maximum_size <= 128 * 1024 * 1024:
        raise PermissionDenied()
    parent = CiphertextFile.open_directory(path.parent)
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
            or first.st_size > maximum_size
        ):
            raise PermissionDenied()
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(maximum_size + 1)
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
            or len(raw) > maximum_size
            or identity(first) != identity(last)
            or identity(last) != identity(named)
        ):
            raise PermissionDenied()
        # Check that the path still points to the directory opened at the start.
        current = CiphertextFile.open_directory(path.parent)
        try:
            selected = os.fstat(current)
            if (directory.st_dev, directory.st_ino) != (
                selected.st_dev,
                selected.st_ino,
            ):
                raise PermissionDenied()
        finally:
            os.close(current)
        return FileSnapshot(identity(last), raw)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)
