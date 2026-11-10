"""Standalone convenience API. Importing it does not activate encrypted I/O."""

import atexit
import builtins
import getpass
import io
import os
import sys
import threading
from pathlib import Path

from .encrypted_io import EncryptedIOContext, PasswordRequest
from .errors import ActivationConflict, InteractionRequired

_CONTEXT: EncryptedIOContext | None = None
_CONTEXT_LOCK = threading.RLock()


def request_password(prompt: str) -> str:
    """Read a password from a terminal without showing it.

    Args:
        prompt: Text shown before reading the password.

    Returns:
        The entered password. Non-interactive input raises InteractionRequired.
    """
    if not sys.stdin.isatty():
        raise InteractionRequired()
    return getpass.getpass(prompt)


def _terminal_password(request: PasswordRequest) -> str:
    prompts = {
        "master": "Master password: ",
        "master_confirm": "Master password confirm: ",
        "file": f"Password for {request.source}: ",
    }
    return request_password(prompts[request.kind])


def create_context() -> EncryptedIOContext:
    """Create an owned standalone context without activating global file reads.

    Uses the selected standalone keystore and terminal password input. Construction
    does not open the store or request a password. The caller must close the context.
    """
    # Never capture another context's decryptor as the raw file opener.
    opener = builtins.open
    if getattr(getattr(opener, "__self__", None), "_w3plex_security_context", False):
        opener = io.open
    legacy_path = os.environ.get("W3PLEX_KEYSTORE")
    modern_path = os.environ.get("W3PLEX_SECRET_STORE")
    if (
        legacy_path
        and modern_path
        and (
            Path(legacy_path).expanduser().absolute()
            != Path(modern_path).expanduser().absolute()
        )
    ):
        raise ValueError(
            "Use one keystore path: W3PLEX_KEYSTORE and W3PLEX_SECRET_STORE differ"
        )
    path = Path(legacy_path or modern_path or "~/.keystore.bin").expanduser()
    return EncryptedIOContext(
        legacy_keystore_path=path,
        keystore_path=path,
        input_handler=_terminal_password,
        opener=opener,
        persist_keys=True,
        persist_legacy_keys=True,
    )


def default_context() -> EncryptedIOContext:
    """Get or create the shared context used by standalone helpers.

    Returns:
        The shared EncryptedIOContext. This call does not install it as builtins.open.
    """
    global _CONTEXT
    with _CONTEXT_LOCK:
        if _CONTEXT is None:
            _CONTEXT = create_context()
            atexit.register(_CONTEXT.close)
        return _CONTEXT


def enable_encrypted_io() -> EncryptedIOContext:
    """Enable encrypted reads through the standalone context.

    Returns:
        The active EncryptedIOContext. Repeated calls by the same owner are allowed.
    """
    with _CONTEXT_LOCK:
        context = default_context()
        if not context.active:
            context.enable()
        return context


def disable_encrypted_io() -> None:
    """Restore the opener used before standalone encrypted reads.

    Returns:
        None.
    """
    with _CONTEXT_LOCK:
        if _CONTEXT is None:
            raise ActivationConflict()
        _CONTEXT.disable()


def unlock_keystore() -> None:
    """Prepare and unlock the standalone context's key store.

    Returns:
        None.
    """
    default_context().unlock_keystore()


def encrypt_file(
    src: str | Path,
    *,
    password: str | None = None,
    dst: str | Path | None = None,
    inplace: bool = False,
    add_to_keystore: bool = False,
) -> Path:
    """Encrypt a file through the standalone context.

    Args:
        src: Path of the source file.
        password: File password. None requests a password through the input callback.
        dst: Output path. None uses the source path with .enc added.
        inplace: If True, replace the source file instead of writing to dst.
        add_to_keystore: Whether to save the file key for later reads.

    Returns:
        The path of the encrypted output file.
    """
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
    """Decrypt a file through the standalone context.

    Args:
        src: Path of the encrypted source file.
        password: File password. None uses key lookup or the input callback.
        dst: Output path. None uses the source path with a .dec suffix.
        inplace: If True, replace the source file instead of writing to dst.
        use_keystore: Whether saved keys can be used when no password is given.

    Returns:
        The path of the decrypted output file.
    """
    return default_context().decrypt_file(
        src, password=password, dst=dst, inplace=inplace, use_keystore=use_keystore
    )


def encrypt_data(
    data: str | bytes, *, password: str | None = None, add_to_keystore: bool = True
) -> tuple[str, str]:
    """Encrypt bytes or text through the standalone context.

    Args:
        data: Bytes or text to encrypt. Text is encoded as UTF-8.
        password: File password. None creates a random password when key saving is
            enabled.
        add_to_keystore: Whether to save the key for later reads.

    Returns:
        A pair containing base64 encrypted text and the password used.
    """
    return default_context().encrypt_data(
        data, password=password, add_to_keystore=add_to_keystore
    )


def decrypt_data(
    encrypted: str, *, password: str | None = None, use_keystore: bool = True
) -> str:
    """Decrypt base64 input through the standalone context.

    Args:
        encrypted: Base64 text containing encrypted data.
        password: Optional file password. Without it, saved keys may be used.
        use_keystore: Whether to allow saved keys when no password is given.

    Returns:
        Decrypted text for a supported container, otherwise the original input string.
    """
    return default_context().decrypt_data(
        encrypted, password=password, use_keystore=use_keystore
    )
