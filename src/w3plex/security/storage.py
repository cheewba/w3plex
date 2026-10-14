"""Bounded ciphertext storage, pinned paths and atomic exclusive writes."""

import hashlib
import os
import secrets
import stat
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
    fingerprint: bytes = b""


def _identity(value: os.stat_result) -> FileIdentity:
    return FileIdentity(
        value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns
    )


class CiphertextFile:
    def __init__(
        self,
        path: str | Path,
        *,
        maximum_size: int = 8 * 1024 * 1024,
    ):
        if os.name != "posix" or not all(
            hasattr(os, name) for name in ("O_NOFOLLOW", "O_DIRECTORY")
        ):
            raise UnsupportedProtection()
        self.path = Path(os.path.abspath(path))
        if self.path.name in {"", ".", ".."}:
            raise UnsafeStorage()
        self.maximum_size = maximum_size
        self._fd = self.open_directory(self.path.parent)
        try:
            info = self.check_directory(self._fd)
            self._directory_identity = (info.st_dev, info.st_ino)
        except BaseException:
            self.close()
            raise

    def __repr__(self):
        return "CiphertextFile(<private>)"

    @staticmethod
    def open_directory(path: Path) -> int:
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
        current = self.open_directory(self.path.parent)
        try:
            info = self.check_directory(current)
            if (info.st_dev, info.st_ino) != self._directory_identity:
                raise UnsafeStorage()
        finally:
            os.close(current)

    @staticmethod
    def _check_file(info: os.stat_result):
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise UnsafeStorage()

    def check_directory(self, descriptor: int) -> os.stat_result:
        """Validate an opened directory; applications may add access policy."""
        info = os.fstat(descriptor)
        if not stat.S_ISDIR(info.st_mode):
            raise UnsafeStorage()
        return info

    def check_file(self, descriptor: int) -> os.stat_result:
        """Validate an opened file before use, including lock and temporary files."""
        info = os.fstat(descriptor)
        self._check_file(info)
        return info

    def _file_identity(self, fd: int) -> FileIdentity:
        before = self.check_file(fd)
        if before.st_size > self.maximum_size:
            raise UnsafeStorage()
        digest = hashlib.sha256()
        size = 0
        while size <= self.maximum_size:
            block = os.pread(fd, min(65536, self.maximum_size + 1 - size), size)
            if not block:
                break
            digest.update(block)
            size += len(block)
        after = self.check_file(fd)
        if (
            size != before.st_size
            or size > self.maximum_size
            or _identity(before) != _identity(after)
        ):
            raise StoreChanged()
        return _identity(after)._replace(fingerprint=digest.digest())

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
            identity = self._file_identity(fd)
            if identity._replace(fingerprint=b"") != _identity(info):
                raise StoreChanged()
            return identity
        finally:
            os.close(fd)

    def read(self) -> tuple[bytes, FileIdentity]:
        self._check_directory()
        fd = os.open(
            self.path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self._fd
        )
        try:
            before = self.check_file(fd)
            if before.st_size > self.maximum_size:
                raise UnsafeStorage()
            with os.fdopen(fd, "rb", closefd=False) as stream:
                data = stream.read(self.maximum_size + 1)
            after = self.check_file(fd)
            identity = _identity(before)._replace(
                fingerprint=hashlib.sha256(data).digest()
            )
            if (
                len(data) > self.maximum_size
                or _identity(before) != _identity(after)
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
            info = self.check_file(fd)
            self._check_file(info)
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

    def identity(self) -> FileIdentity | None:
        """Check the approved target before a caller prepares its replacement."""
        self._check_directory()
        return self._target_identity()

    def write_plaintext(
        self, plaintext: bytes, *, expected: FileIdentity | None
    ) -> None:
        """Explicit final plaintext output, with no plaintext temporary file.

        This direct output is not atomic; interruption can leave a partial final
        file. Ciphertext commits must use write instead.
        """
        if type(plaintext) is not bytes or len(plaintext) > self.maximum_size:
            raise UnsafeStorage()
        with self._writer():
            if self._target_identity() != expected:
                raise StoreChanged()
            flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
            if expected is None:
                flags |= os.O_CREAT | os.O_EXCL
            fd = os.open(self.path.name, flags, 0o600, dir_fd=self._fd)
            try:
                info = self.check_file(fd)
                self._check_file(info)
                if expected is not None and self._file_identity(fd) != expected:
                    raise StoreChanged()
                self._check_directory()
                os.fchmod(fd, 0o600)
                self.check_file(fd)
                if self._target_identity() != self._file_identity(fd):
                    raise StoreChanged()
                os.ftruncate(fd, 0)
                with os.fdopen(fd, "wb", closefd=False) as stream:
                    stream.write(plaintext)
                    stream.flush()
                    os.fsync(fd)
                named = self._target_identity()
                if named != self._file_identity(fd):
                    raise StoreChanged()
                if self._fd is None:
                    raise UnsafeStorage()
                os.fsync(self._fd)
                self._check_directory()
            finally:
                os.close(fd)

    def write(
        self, ciphertext: bytes, *, expected: FileIdentity | None
    ) -> FileIdentity:
        """Commit a complete ciphertext; expected=None means exclusive creation.

        On a failure after publication, the complete new file can already be visible.
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
                os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=self._fd,
            )
            try:
                with os.fdopen(descriptor, "wb", closefd=False) as stream:
                    self.check_file(stream.fileno())
                    stream.write(ciphertext)
                    stream.flush()
                    os.fsync(stream.fileno())
                self._check_directory()
                created = self.check_file(descriptor)
                named = os.stat(temporary, dir_fd=self._fd, follow_symlinks=False)
                if _identity(created) != _identity(named):
                    raise StoreChanged()
                if (
                    self._file_identity(descriptor).fingerprint
                    != hashlib.sha256(ciphertext).digest()
                ):
                    raise StoreChanged()
                if self._target_identity() != expected:
                    raise StoreChanged()
                if expected is None:
                    collision = False
                    try:
                        # link() atomically refuses an occupied destination,
                        # including writers which ignore the advisory lock.
                        os.link(
                            temporary,
                            self.path.name,
                            src_dir_fd=self._fd,
                            dst_dir_fd=self._fd,
                            follow_symlinks=False,
                        )
                    except FileExistsError:
                        collision = True
                    if collision:
                        raise StoreChanged()
                    os.unlink(temporary, dir_fd=self._fd)
                else:
                    os.replace(
                        temporary,
                        self.path.name,
                        src_dir_fd=self._fd,
                        dst_dir_fd=self._fd,
                    )
                if self._fd is None:
                    raise UnsafeStorage()
                os.fsync(self._fd)
                self._check_directory()
                identity = self._target_identity()
                if identity is None or identity != self._file_identity(descriptor):
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
