"""Run on a real POSIX kernel without third-party Python dependencies.

Load only the stdlib native-control modules. This is a capability prototype,
not a full vault/signing/HTTP acceptance test. Dumps, if any, stay in a temporary
directory and are deleted with it. Never upload them.
"""

import importlib
import json
import mmap
import os
import platform
import signal
import subprocess
import sys
import tempfile
import types
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[2] / "src/w3plex/security"
package = types.ModuleType("security_control_probe")
package.__path__ = [str(SOURCE)]
sys.modules[package.__name__] = package
memory = importlib.import_module(package.__name__ + ".memory")


def main():
    protection = memory.ProcessProtection()
    status = protection.activate()
    with memory.LockedBuffer(
        b"PUBLIC-TEST-native-secret", protection=protection
    ) as buffer:
        assert buffer.copy_bytes() == b"PUBLIC-TEST-native-secret"
        if sys.platform == "linux":
            current = Path("/proc/self/status").read_text()
            locked = next(
                line for line in current.splitlines() if line.startswith("VmLck:")
            )
            assert int(locked.split()[1]) >= mmap.PAGESIZE // 1024
            # Check the actual mapping's dump-exclusion flag.
            address = buffer._address
            matched = False
            for line in Path("/proc/self/smaps").read_text().splitlines():
                if "-" in line.split()[0]:
                    interval = line.split()[0].split("-")
                    matched = int(interval[0], 16) <= address < int(interval[1], 16)
                elif matched and line.startswith("VmFlags:"):
                    assert "dd" in line.split()
                    break
            else:
                raise AssertionError("Mapping flags missing")
    with tempfile.TemporaryDirectory(prefix="cryptopal-core-probe-") as directory:
        code = "import resource,os,signal;resource.setrlimit(resource.RLIMIT_CORE,(0,0));os.kill(os.getpid(),signal.SIGABRT)"
        if sys.platform == "linux":
            code = (
                "import ctypes;lib=ctypes.CDLL(None);assert lib.prctl(4,0,0,0,0)==0;"
                + code
            )
        child = subprocess.Popen(
            [sys.executable, "-I", "-c", code],
            cwd=directory,
            env={"PATH": "/usr/local/bin:/usr/bin:/bin"},
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        child.wait(timeout=20)
        assert child.returncode == -signal.SIGABRT
        assert not list(Path(directory).iterdir())
    print(
        json.dumps(
            {
                "platform": platform.platform(),
                "python": platform.python_version(),
                "uid": os.getuid(),
                "core_files_disabled": status.core_files_disabled,
                "inspection_restricted": status.inspection_restricted,
                "native_lock": "passed",
                "native_dump_exclusion": "passed"
                if sys.platform == "linux"
                else "not supported by this helper",
                "SIGABRT_core_route": "no file in temporary cwd",
                "limitations": "No crypto/TLS/CLI copies, external collector or privileged snapshot were tested.",
            }
        )
    )


if __name__ == "__main__":
    main()
