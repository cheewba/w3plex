"""Explicit POSIX process controls and locked, private native allocations.

This controls owned pages and core-file production. It cannot protect a full
privileged snapshot or erase immutable copies made by Python/crypto libraries.
Native Windows controls require a separately verified implementation.
"""

import ctypes
import mmap
import os
import sys
from dataclasses import dataclass

from .errors import UnsupportedProtection


@dataclass(frozen=True)
class ProtectionStatus:
    platform: str
    core_files_disabled: bool
    inspection_restricted: bool
    process_id: int


class ProcessProtection:
    def __init__(self):
        self._status: ProtectionStatus | None = None

    def activate(self) -> ProtectionStatus:
        """Irreversibly lower this process's core limit before private input.

        Only the trusted process bootstrap should call this. No policy changes
        happen on import. Inspection restriction is currently Linux-specific.
        """
        if sys.platform not in {"darwin", "linux"}:
            raise UnsupportedProtection()
        import resource

        ok = False
        inspection = False
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
        except (OSError, ValueError, AttributeError):
            pass
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
    """Own one private page allocation; check mlock before copying any secret.

    ``copy_bytes`` is service-internal and creates an immutable dependency copy.
    This object must never cross a model/RPC boundary. It is not an in-process
    security boundary. Close explicitly; do not rely on finalizers for locking.
    """

    def __init__(self, value: bytes, *, protection: ProcessProtection):
        protection.check()
        if not value or len(value) > 65536:
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
        if self._memory is None or self._pid != os.getpid():
            raise UnsupportedProtection()
        return self._memory[: self._size]

    def replace(self, value: bytes) -> None:
        """Copy into already protected pages; never resize a secret allocation."""
        if self._memory is None or self._pid != os.getpid():
            raise UnsupportedProtection()
        if not isinstance(value, bytes) or len(value) != self._size:
            raise ValueError("Invalid secret buffer size")
        self._memory[: self._size] = value

    def close(self):
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
