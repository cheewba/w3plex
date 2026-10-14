"""Lock and close must not publish private cleanup exception types or text."""

import pytest

from w3plex.security import EncryptedIOContext
from w3plex.security.errors import (
    PermissionDenied,
    SecurityError,
    UnsupportedProtection,
)
from w3plex.security.memory import LockedBuffer, ProcessProtection
from w3plex.security.storage import CiphertextFile
from w3plex.security.vault import Vault


@pytest.mark.parametrize(
    "operation", ["vault-lock", "vault-close", "context-lock", "context-close"]
)
@pytest.mark.parametrize("failure", ["listener", "vault-buffer", "file-buffer"])
@pytest.mark.parametrize("error_kind", ["custom", "modified-trusted"])
def test_cleanup_errors_are_sanitized_without_skipping_data_owners(
    tmp_path, monkeypatch, operation, failure, error_kind
):
    class PrivateFailure(SecurityError):
        code = "PUBLIC-TEST-private-error-code"

        def __str__(self):
            return "PUBLIC-TEST-private-error-message"

    def fail():
        error = PrivateFailure() if error_kind == "custom" else PermissionDenied()
        error.args = ("PUBLIC-TEST-private-error-argument",)
        error.code = "PUBLIC-TEST-private-instance-code"
        raise error from ValueError("PUBLIC-TEST-private-error-cause")

    class Host:
        calls = 0

        def locked(self):
            self.calls += 1
            if failure == "listener":
                fail()

    class Observer:
        calls = 0

        def locked(self):
            self.calls += 1

    protection = ProcessProtection()
    protection.activate()
    vault = Vault(CiphertextFile(tmp_path / "vault"), protection=protection)
    owner = EncryptedIOContext(protection=protection, keystore=vault)
    host, observer = Host(), Observer()
    vault.bind_lock(host.locked)
    vault.add_lock_listener(observer.locked)
    buffers = [
        LockedBuffer(b"PUBLIC-TEST-owned-key", protection=protection) for _ in range(3)
    ]
    vault._key = buffers[0]
    owner._keys = {"first": buffers[1], "second": buffers[2]}
    if failure != "listener":
        buffer = buffers[0 if failure == "vault-buffer" else 1]
        close = buffer.close

        def interrupted_close():
            close()
            fail()

        monkeypatch.setattr(buffer, "close", interrupted_close)
    expected = SecurityError if error_kind == "custom" else PermissionDenied
    try:
        with pytest.raises(SecurityError) as result:
            if operation == "vault-lock":
                vault.lock()
            elif operation == "vault-close":
                vault.close()
            elif operation == "context-lock":
                owner.lock()
            else:
                owner.close()
        assert type(result.value) is expected
        assert str(result.value) == expected.code
        assert result.value.__cause__ is None and result.value.__context__ is None
        assert host.calls == 1 and observer.calls == 1
        assert vault._key is None and owner._keys == {} and not vault.is_unlocked
        for buffer in buffers:
            with pytest.raises(UnsupportedProtection):
                buffer.copy_bytes()
    finally:
        vault.bind_lock(None)
        monkeypatch.undo()
        owner.close()
        vault.close()
