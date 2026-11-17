"""Exclusive encrypted-open activation and explicit standalone activation."""

import builtins
import subprocess
import sys

import pytest

from w3plex.security.errors import ActivationConflict
from w3plex.security.files.legacy import LegacyContext


def test_grouped_modules_preserve_existing_imports_without_activation(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            "-c",
            """import builtins
previous = builtins.open
from w3plex.security import _crypto, encrypted_io, file_format, storage, vault
from w3plex.security.crypto import primitives
from w3plex.security.files import encrypted_io as grouped_io, format as grouped_format
from w3plex.security.stores import file as grouped_storage, vault as grouped_vault
assert _crypto is primitives
assert encrypted_io is grouped_io
assert file_format is grouped_format
assert storage is grouped_storage
assert vault is grouped_vault
assert builtins.open is previous
""",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_standalone_activation_cannot_capture_an_active_context(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """import builtins
from w3plex.security.legacy import LegacyContext
previous = builtins.open
from w3plex.security import enable_encrypted_io, disable_encrypted_io
from w3plex.security.errors import ActivationConflict
context = LegacyContext("missing-keystore")
with context.activated():
    owned = builtins.open
    try:
        enable_encrypted_io()
    except ActivationConflict:
        pass
    else:
        raise AssertionError("Legacy import must reject a conflicting context")
    assert builtins.open is owned
assert builtins.open is previous
standalone = enable_encrypted_io()
assert builtins.open.__self__ is standalone
assert enable_encrypted_io() is standalone
disable_encrypted_io()
assert builtins.open is previous
""",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_explicit_activation_restores_previous_and_rejects_conflicts(tmp_path):
    a, b = LegacyContext(tmp_path / "a"), LegacyContext(tmp_path / "b")
    previous = builtins.open
    with a.activated():
        installed = builtins.open
        assert installed.__self__ is a
        with pytest.raises(ActivationConflict):
            b.enable()
        with pytest.raises(ActivationConflict):
            a.enable()
        builtins.open = previous
        with pytest.raises(ActivationConflict):
            a.disable()
        builtins.open = installed
    assert builtins.open is previous
