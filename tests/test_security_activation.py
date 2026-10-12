"""Exclusive encrypted-open activation and the legacy automatic facade."""

import builtins
import subprocess
import sys

import pytest

from w3plex.security.errors import ActivationConflict
from w3plex.security.legacy import LegacyContext


def test_legacy_import_cannot_capture_an_active_new_context(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """import builtins
from w3plex.security.legacy import LegacyContext
previous = builtins.open
context = LegacyContext("missing-keystore")
with context.activated():
    owned = builtins.open
    try:
        import w3plex.secure
    except Exception as error:
        assert type(error).__name__ == "SecureError"
    else:
        raise AssertionError("Legacy import must reject a conflicting context")
    assert builtins.open is owned
assert builtins.open is previous
from w3plex import secure
assert builtins.open is secure._secure_open
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
