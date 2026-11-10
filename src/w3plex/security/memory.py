"""Explicit POSIX process controls and locked, private native allocations.

This controls owned pages, core-file production and debugger attachment. It
cannot protect a full privileged snapshot or erase immutable Python/crypto copies.
Native Windows controls require a separately verified implementation.
"""

import ctypes
import mmap
import os
import sys
from dataclasses import dataclass

from .errors import UnsupportedProtection

_PT_DENY_ATTACH = 31


@dataclass(frozen=True)
class ProtectionStatus:
    """Describe the protection enabled for a process.

    Args:
        platform: Name of the platform where the controls were enabled.
        core_files_disabled: Whether core dump files are disabled.
        inspection_restricted: Whether the supported OS inspection controls were
            applied.
        process_id: ID of the process to which the protection applies.
    """

    platform: str
    core_files_disabled: bool
    inspection_restricted: bool
    process_id: int


class ProcessProtection:
    """Enable and check process protection before using secrets."""

    def __init__(self):
        self._status: ProtectionStatus | None = None

    def activate(self) -> ProtectionStatus:
        """Enable process protection before reading passwords.

        This lowers the core dump limit for the rest of the process. On macOS it blocks
        future debugger connections. Calling it while a debugger is attached can end the
        process.

        Returns:
            ProtectionStatus describing the active controls and process ID.
        """
        if sys.platform not in {"darwin", "linux"}:
            raise UnsupportedProtection()
        import resource

        ok = False
        inspection = False
        self._status = None
        try:
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            ok = resource.getrlimit(resource.RLIMIT_CORE) == (0, 0)
            if sys.platform == "linux":
                lib = ctypes.CDLL(None, use_errno=True)
                lib.prctl.argtypes = [
                    ctypes.c_int,
                    ctypes.c_ulong,
                    ctypes.c_ulong,
                    ctypes.c_ulong,
                    ctypes.c_ulong,
                ]
                lib.prctl.restype = ctypes.c_int
                inspection = (
                    lib.prctl(4, 0, 0, 0, 0) == 0 and lib.prctl(3, 0, 0, 0, 0) == 0
                )
                ok = ok and inspection
            else:
                lib = ctypes.CDLL(None, use_errno=True)
                lib.ptrace.argtypes = [
                    ctypes.c_int,
                    ctypes.c_int,
                    ctypes.c_void_p,
                    ctypes.c_int,
                ]
                lib.ptrace.restype = ctypes.c_int
                inspection = lib.ptrace(_PT_DENY_ATTACH, 0, None, 0) == 0
                ok = ok and inspection
        except (OSError, ValueError, AttributeError):
            ok = False
        if not ok:
            raise UnsupportedProtection()
        self._status = ProtectionStatus(sys.platform, True, inspection, os.getpid())
        ready = False
        try:
            with LockedBuffer(bytes(32), protection=self):
                ready = True
        except (OSError, ValueError, AttributeError, UnsupportedProtection):
            pass
        if not ready:
            self._status = None
            raise UnsupportedProtection()
        return self._status

    def check(self):
        """Check that protection is active for this process and platform.

        Returns:
            None.
        """
        if (
            self._status is None
            or self._status.process_id != os.getpid()
            or self._status.platform != sys.platform
        ):
            raise UnsupportedProtection()
        import resource

        if resource.getrlimit(resource.RLIMIT_CORE) != (0, 0):
            raise UnsupportedProtection()
        if sys.platform == "linux":
            lib = ctypes.CDLL(None)
            lib.prctl.argtypes = [
                ctypes.c_int,
                ctypes.c_ulong,
                ctypes.c_ulong,
                ctypes.c_ulong,
                ctypes.c_ulong,
            ]
            lib.prctl.restype = ctypes.c_int
            if lib.prctl(3, 0, 0, 0, 0) != 0:
                raise UnsupportedProtection()


class LockedBuffer:
    """Keep bytes in locked native memory.

    Pages are locked before the value is copied. copy_bytes() creates a normal Python
    bytes copy, which must stay private. Close the buffer explicitly. It belongs in
    trusted code, not RPC or model responses. It does not isolate secrets from other
    code in the same process.
    """

    def __init__(
        self,
        value: bytes,
        *,
        protection: ProcessProtection,
        max_size: int = 65536,
    ):
        """Lock memory pages before copying a value into them.

        Args:
            value: Non-empty bytes to keep in the buffer.
            protection: Active protection for the current process.
            max_size: Largest value allowed, in bytes. The buffer cannot grow after
                creation.

        Returns:
            None.
        """
        protection.check()
        if type(max_size) is not int or not 1 <= max_size <= 1024 * 1024:
            raise ValueError("Invalid secret buffer limit")
        if not value or len(value) > max_size:
            raise ValueError("Invalid secret buffer size")
        self._size = len(value)
        self._capacity = (
            (self._size + mmap.PAGESIZE - 1) // mmap.PAGESIZE
        ) * mmap.PAGESIZE
        self._memory = None
        self._pid = os.getpid()
        lib = ctypes.CDLL(None, use_errno=True)
        required = ("mlock", "munlock", "explicit_bzero")
        if sys.platform == "linux":
            required += ("madvise",)
        if not all(hasattr(lib, name) for name in required):
            raise UnsupportedProtection()
        lib.mlock.argtypes = lib.munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        lib.mlock.restype = lib.munlock.restype = ctypes.c_int
        lib.explicit_bzero.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        lib.explicit_bzero.restype = None
        self._lib = lib
        # MAP_PRIVATE is deliberate: the default Unix mmap can be shared.
        area = mmap.mmap(
            -1,
            self._capacity,
            flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS,
            prot=mmap.PROT_READ | mmap.PROT_WRITE,
        )
        address = ctypes.addressof(ctypes.c_char.from_buffer(area))
        if lib.mlock(address, self._capacity) != 0:
            area.close()
            raise UnsupportedProtection()
        if sys.platform == "linux":
            lib.madvise.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
            lib.madvise.restype = ctypes.c_int
            # Linux MADV_DONTDUMP. Refuse kernels that cannot apply it.
            if lib.madvise(address, self._capacity, 16) != 0:
                lib.munlock(address, self._capacity)
                area.close()
                raise UnsupportedProtection()
        self._address = address
        self._memory = area
        area[: self._size] = value

    def __repr__(self):
        return "LockedBuffer(<private>)"

    def copy_bytes(self) -> bytes:
        """Copy the stored value into a Python bytes object.

        Returns:
            A bytes copy of the value. The copy is outside the locked buffer.
        """
        if self._memory is None or self._pid != os.getpid():
            raise UnsupportedProtection()
        return self._memory[: self._size]

    def replace(self, value: bytes) -> None:
        """Replace the value without changing the buffer size.

        Args:
            value: New bytes. Their length must match the original value.

        Returns:
            None.
        """
        if self._memory is None or self._pid != os.getpid():
            raise UnsupportedProtection()
        if not isinstance(value, bytes) or len(value) != self._size:
            raise ValueError("Invalid secret buffer size")
        self._memory[: self._size] = value

    def close(self):
        """Clear the memory pages, unlock them and release the buffer.

        Returns:
            None.
        """
        area = self._memory
        if area is None:
            return
        self._lib.explicit_bzero(self._address, self._capacity)
        result = self._lib.munlock(self._address, self._capacity)
        area.close()
        self._memory = None
        if result != 0:
            raise UnsupportedProtection()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
