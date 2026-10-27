"""Explicit native controls and failure before private input or key allocation."""

import ctypes
import os
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import Mock

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


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin debugger control")
@pytest.mark.parametrize("failure", ["unavailable", "refused"])
def test_darwin_debugger_control_failure_blocks_secrets_and_can_recover(
    protection, monkeypatch, failure
):
    native = ctypes.CDLL(None, use_errno=True)
    library = SimpleNamespace(
        mlock=native.mlock,
        munlock=native.munlock,
        explicit_bzero=native.explicit_bzero,
    )
    if failure == "refused":
        library.ptrace = Mock(return_value=-1)
    with monkeypatch.context() as patch:
        patch.setattr("w3plex.security.memory.ctypes.CDLL", lambda *a, **kw: library)
        with pytest.raises(UnsupportedProtection):
            protection.activate()
        with pytest.raises(UnsupportedProtection):
            protection.check()
        with pytest.raises(UnsupportedProtection):
            LockedBuffer(VALUE, protection=protection)
    assert protection.activate().inspection_restricted
    with LockedBuffer(VALUE, protection=protection) as buffer:
        assert buffer.copy_bytes() == VALUE


def test_native_buffer_clear_and_close(protection, monkeypatch):
    buffer = LockedBuffer(VALUE, protection=protection)
    area = buffer._memory
    copied = buffer.copy_bytes()
    assert isinstance(copied, bytes)
    assert copied == VALUE
    buffer.replace(b"x" * len(VALUE))
    assert buffer.copy_bytes() == b"x" * len(VALUE)
    assert copied == VALUE
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
    with pytest.raises(UnsupportedProtection):
        buffer.replace(VALUE)
    assert copied == VALUE


def test_context_manager_closes_buffer_when_body_raises(protection):
    buffer = LockedBuffer(VALUE, protection=protection)
    area = buffer._memory
    with (
        pytest.raises(RuntimeError, match="public-test-failure"),
        buffer as entered,
    ):
        assert entered is buffer
        assert entered.copy_bytes() == VALUE
        raise RuntimeError("public-test-failure")
    assert area.closed
    with pytest.raises(UnsupportedProtection):
        buffer.copy_bytes()


def test_process_and_buffer_reject_different_pid(protection, monkeypatch):
    owner_pid = os.getpid()
    with LockedBuffer(VALUE, protection=protection) as buffer:
        with monkeypatch.context() as patch:
            patch.setattr("w3plex.security.memory.os.getpid", lambda: owner_pid + 1)
            with pytest.raises(UnsupportedProtection):
                protection.check()
            with pytest.raises(UnsupportedProtection):
                LockedBuffer(VALUE, protection=protection)
            with pytest.raises(UnsupportedProtection):
                buffer.copy_bytes()
            with pytest.raises(UnsupportedProtection):
                buffer.replace(b"x" * len(VALUE))
        protection.check()
        assert buffer.copy_bytes() == VALUE


def test_core_policy_is_explicit_and_irreversible_in_child(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """import builtins, os, resource, sys
before = resource.getrlimit(resource.RLIMIT_CORE)
previous_open = builtins.open
from w3plex.security.memory import ProcessProtection
assert resource.getrlimit(resource.RLIMIT_CORE) == before
assert builtins.open is previous_open
protection = ProcessProtection()
assert resource.getrlimit(resource.RLIMIT_CORE) == before
status = protection.activate()
assert status.core_files_disabled
assert status.inspection_restricted
assert status.process_id == os.getpid()
assert status.platform == sys.platform
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
