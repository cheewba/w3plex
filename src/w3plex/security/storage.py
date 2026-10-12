"""Owner-only POSIX ciphertext storage, pinned directories and exclusive writers.

Windows storage is refused until its native DACL/reparse implementation passes
verification. chmod on Windows does not satisfy this contract.
"""

import ctypes
import errno
import os
import secrets
import stat
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import NamedTuple

from .errors import SecurityError, UnsupportedProtection


class UnsafeStorage(SecurityError):
    code = "unsafe_storage"


class StoreChanged(SecurityError):
    code = "store_changed"


class WriterBusy(SecurityError):
    code = "writer_busy"


class FileIdentity(NamedTuple):
    device: int
    inode: int
    size: int
    modified_ns: int
    changed_ns: int


def _identity(value: os.stat_result) -> FileIdentity:
    return FileIdentity(
        value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns
    )


def _no_extended_acl(fd: int) -> None:
    if sys.platform != "darwin":
        return
    lib = ctypes.CDLL(None, use_errno=True)
    if not all(hasattr(lib, name) for name in ("acl_get_fd_np", "acl_free")):
        raise UnsupportedProtection()
    lib.acl_get_fd_np.argtypes = [ctypes.c_int, ctypes.c_int]
    lib.acl_get_fd_np.restype = ctypes.c_void_p
    lib.acl_free.argtypes = [ctypes.c_void_p]
    lib.acl_free.restype = ctypes.c_int
    ctypes.set_errno(0)
    # Darwin ACL_TYPE_EXTENDED. ENOENT denotes no extended ACL on this fd.
    acl = lib.acl_get_fd_np(fd, 0x100)
    if acl:
        if lib.acl_free(acl) != 0:
            raise UnsupportedProtection()
        raise UnsafeStorage()
    if ctypes.get_errno() != errno.ENOENT:
        raise UnsupportedProtection()


class CiphertextFile:
    def __init__(self, path: str | Path, *, maximum_size: int = 8 * 1024 * 1024):
        if os.name != "posix" or not all(
            hasattr(os, name) for name in ("O_NOFOLLOW", "O_DIRECTORY", "getuid")
        ):
            raise UnsupportedProtection()
        self.path = Path(os.path.abspath(path))
        if self.path.name in {"", ".", ".."}:
            raise UnsafeStorage()
        self.maximum_size = maximum_size
        self._fd = self._open_directory(self.path.parent)
        try:
            info = os.fstat(self._fd)
            self._directory_identity = (info.st_dev, info.st_ino)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise UnsafeStorage()
            _no_extended_acl(self._fd)
        except BaseException:
            self.close()
            raise

    def __repr__(self):
        return "CiphertextFile(<private>)"

    @staticmethod
    def _open_directory(path: Path) -> int:
        descriptor = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
        try:
            for part in path.parts[1:]:
                following = os.open(
                    part,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=descriptor,
                )
                os.close(descriptor)
                descriptor = following
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def _check_directory(self):
        if self._fd is None:
            raise UnsafeStorage()
        current = self._open_directory(self.path.parent)
        try:
            info = os.fstat(current)
            if (
                (info.st_dev, info.st_ino) != self._directory_identity
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700
            ):
                raise UnsafeStorage()
            _no_extended_acl(current)
        finally:
            os.close(current)

    @staticmethod
    def _check_file(info: os.stat_result):
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise UnsafeStorage()

    def _target_identity(self) -> FileIdentity | None:
        try:
            info = os.stat(self.path.name, dir_fd=self._fd, follow_symlinks=False)
        except FileNotFoundError:
            return None
        self._check_file(info)
        fd = os.open(
            self.path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self._fd
        )
        try:
            _no_extended_acl(fd)
            if _identity(os.fstat(fd)) != _identity(info):
                raise StoreChanged()
            return _identity(info)
        finally:
            os.close(fd)

    def read(self) -> tuple[bytes, FileIdentity]:
        self._check_directory()
        fd = os.open(
            self.path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self._fd
        )
        try:
            before = os.fstat(fd)
            self._check_file(before)
            _no_extended_acl(fd)
            if before.st_size > self.maximum_size:
                raise UnsafeStorage()
            with os.fdopen(fd, "rb", closefd=False) as stream:
                data = stream.read(self.maximum_size + 1)
            after = os.fstat(fd)
            identity = _identity(before)
            self._check_file(after)
            _no_extended_acl(fd)
            if (
                len(data) > self.maximum_size
                or identity != _identity(after)
                or self._target_identity() != identity
            ):
                raise StoreChanged()
            self._check_directory()
            return data, identity
        finally:
            os.close(fd)

    @contextmanager
    def _writer(self):
        import fcntl

        self._check_directory()
        lock_name = "." + self.path.name + ".lock"
        fd = os.open(
            lock_name,
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
            0o600,
            dir_fd=self._fd,
        )
        acquired = False
        try:
            info = os.fstat(fd)
            self._check_file(info)
            _no_extended_acl(fd)
            named = os.stat(lock_name, dir_fd=self._fd, follow_symlinks=False)
            if (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino):
                raise UnsafeStorage()
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
            except BlockingIOError:
                pass
            if not acquired:
                raise WriterBusy()
            yield
            self._check_directory()
        finally:
            if acquired:
                fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def write(
        self, ciphertext: bytes, *, expected: FileIdentity | None
    ) -> FileIdentity:
        """Commit a complete ciphertext; expected=None means exclusive creation.

        On a failure after replace, the complete new file can already be visible.
        The caller must invalidate cached state and reread, never retry blindly.
        """
        if (
            not isinstance(ciphertext, bytes)
            or not 1 <= len(ciphertext) <= self.maximum_size
        ):
            raise UnsafeStorage()
        with self._writer():
            if self._target_identity() != expected:
                raise StoreChanged()
            temporary = "." + self.path.name + "." + secrets.token_hex(16) + ".tmp"
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=self._fd,
            )
            try:
                with os.fdopen(descriptor, "wb", closefd=False) as stream:
                    self._check_file(os.fstat(stream.fileno()))
                    _no_extended_acl(stream.fileno())
                    stream.write(ciphertext)
                    stream.flush()
                    os.fsync(stream.fileno())
                self._check_directory()
                created = os.fstat(descriptor)
                self._check_file(created)
                _no_extended_acl(descriptor)
                named = os.stat(temporary, dir_fd=self._fd, follow_symlinks=False)
                if _identity(created) != _identity(named):
                    raise StoreChanged()
                if self._target_identity() != expected:
                    raise StoreChanged()
                os.replace(
                    temporary, self.path.name, src_dir_fd=self._fd, dst_dir_fd=self._fd
                )
                if self._fd is None:
                    raise UnsafeStorage()
                os.fsync(self._fd)
                self._check_directory()
                identity = self._target_identity()
                if identity is None or identity != _identity(os.fstat(descriptor)):
                    raise StoreChanged()
                return identity
            finally:
                os.close(descriptor)
                try:
                    os.unlink(temporary, dir_fd=self._fd)
                except FileNotFoundError:
                    pass

    def close(self):
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
