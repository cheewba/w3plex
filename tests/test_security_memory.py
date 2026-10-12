"""Explicit native controls and failure before private input or key allocation."""

import subprocess
import sys

import pytest

from w3plex.security.errors import UnsupportedProtection
from w3plex.security.memory import LockedBuffer, ProcessProtection

VALUE = b"PUBLIC-TEST-native-secret"


@pytest.fixture
def protection():
    controls = ProcessProtection()
    controls.activate()
    return controls


def test_missing_explicit_protection_blocks_secret_allocation():
    with pytest.raises(UnsupportedProtection):
        LockedBuffer(VALUE, protection=ProcessProtection())


def test_unavailable_locked_memory_invalidates_process_activation(monkeypatch):
    def unavailable(*args, **kwargs):
        raise UnsupportedProtection()

    monkeypatch.setattr("w3plex.security.memory.LockedBuffer", unavailable)
    controls = ProcessProtection()
    with pytest.raises(UnsupportedProtection):
        controls.activate()
    with pytest.raises(UnsupportedProtection):
        controls.check()


def test_native_buffer_clear_and_close(protection, monkeypatch):
    buffer = LockedBuffer(VALUE, protection=protection)
    area = buffer._memory
    assert buffer.copy_bytes() == VALUE
    buffer.replace(b"x" * len(VALUE))
    assert buffer.copy_bytes() == b"x" * len(VALUE)
    with pytest.raises(ValueError):
        buffer.replace(b"short")
    buffer.replace(VALUE)
    assert VALUE.decode() not in repr(buffer)
    original = buffer._lib.munlock
    observed = []

    def inspect(address, capacity):
        observed.append(area[: len(VALUE)])
        return original(address, capacity)

    monkeypatch.setattr(buffer._lib, "munlock", inspect)
    buffer.close()
    assert observed == [b"\0" * len(VALUE)]
    assert area.closed
    buffer.close()
    with pytest.raises(UnsupportedProtection):
        buffer.copy_bytes()


def test_core_policy_is_explicit_and_irreversible_in_child(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """import resource
from w3plex.security.memory import ProcessProtection
before = resource.getrlimit(resource.RLIMIT_CORE)
protection = ProcessProtection()
assert resource.getrlimit(resource.RLIMIT_CORE) == before
status = protection.activate()
assert status.core_files_disabled
assert resource.getrlimit(resource.RLIMIT_CORE) == (0, 0)
protection.check()
""",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 0, result.stderr
