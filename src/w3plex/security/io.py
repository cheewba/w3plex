"""Standalone convenience API. Importing it does not activate encrypted I/O."""

import builtins
import getpass
import io
import os
import sys
import threading
from pathlib import Path

from .errors import ActivationConflict, InteractionRequired
from .legacy import LegacyContext, LegacyPasswordRequest

_CONTEXT: LegacyContext | None = None
_CONTEXT_LOCK = threading.RLock()


def request_password(prompt: str) -> str:
    if not sys.stdin.isatty():
        raise InteractionRequired()
    return getpass.getpass(prompt)


def _terminal_password(request: LegacyPasswordRequest) -> str:
    prompts = {
        "master": "Master password: ",
        "master_confirm": "Master password confirm: ",
        "file": f"Password for {request.source}: ",
    }
    return request_password(prompts[request.kind])


def default_context() -> LegacyContext:
    """Lazy standalone context; independent consumers construct their own."""
    global _CONTEXT
    with _CONTEXT_LOCK:
        if _CONTEXT is None:
            # Never capture another context's decryptor as the raw file opener.
            opener = builtins.open
            if getattr(
                getattr(opener, "__self__", None), "_w3plex_security_context", False
            ):
                opener = io.open
            _CONTEXT = LegacyContext(
                Path(
                    os.environ.get(
                        "W3PLEX_KEYSTORE", str(Path.home() / ".keystore.bin")
                    )
                ).expanduser(),
                input_handler=_terminal_password,
                opener=opener,
                persist_keys=True,
            )
        return _CONTEXT


def enable_encrypted_io() -> LegacyContext:
    """Activate standalone reads; repeated activation by the same owner is safe."""
    with _CONTEXT_LOCK:
        context = default_context()
        if not context.active:
            context.enable()
        return context


def disable_encrypted_io() -> None:
    with _CONTEXT_LOCK:
        if _CONTEXT is None:
            raise ActivationConflict()
        _CONTEXT.disable()


def unlock_keystore() -> None:
    default_context().unlock_keystore()


def encrypt_file(
    src: str | Path,
    *,
    password: str | None = None,
    dst: str | Path | None = None,
    inplace: bool = False,
    add_to_keystore: bool = False,
) -> Path:
    return default_context().encrypt_file(
        src,
        password=password,
        dst=dst,
        inplace=inplace,
        add_to_keystore=add_to_keystore,
    )


def decrypt_file(
    src: str | Path,
    *,
    password: str | None = None,
    dst: str | Path | None = None,
    inplace: bool = False,
    use_keystore: bool = False,
) -> Path:
    return default_context().decrypt_file(
        src, password=password, dst=dst, inplace=inplace, use_keystore=use_keystore
    )


def encrypt_data(
    data: str | bytes, *, password: str | None = None, add_to_keystore: bool = True
) -> tuple[str, str]:
    return default_context().encrypt_data(
        data, password=password, add_to_keystore=add_to_keystore
    )


def decrypt_data(
    encrypted: str, *, password: str | None = None, use_keystore: bool = True
) -> str:
    return default_context().decrypt_data(
        encrypted, password=password, use_keystore=use_keystore
    )
