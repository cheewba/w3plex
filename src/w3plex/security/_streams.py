"""Shared file reading for modern and legacy encrypted files."""

import io
import os
from collections.abc import Callable

from .errors import AuthenticationFailed, InvalidStore

# Sample enough header bytes to identify current and known encrypted formats.
_FORMAT_PROBE_BYTES = 16
# Password failures are bounded to three attempts for a captured source.
_PASSWORD_ATTEMPTS = 3


def decrypted_stream(
    handle,
    *,
    file,
    mode: str,
    encoding: str | None,
    errors: str | None,
    newline: str | None,
    maximum_size: int,
    detect: Callable[[bytes], str],
    decrypt: Callable[..., bytes],
    on_failure: Callable[[str, int], None],
    name: str | None = None,
):
    """Return a file stream, decrypting encrypted read-only input.

    Encrypted source streams are closed before password input. Wrong passwords allow up
    to three attempts.

    Args:
        handle: The stream opened by the context. Plain input is returned without
            closing it.
        file: The original path or file descriptor passed to open().
        mode: The open mode. Descriptors, write modes and streams that cannot seek pass
            through.
        encoding: Encoding used to read decrypted bytes as text.
        errors: How the text reader handles decoding errors.
        newline: How the text reader handles line endings.
        maximum_size: Largest encrypted input allowed, in bytes.
        detect: Callback returning plain, legacy or modern for the first bytes of the
            file.
        decrypt: Callback taking raw bytes and source=path, and returning decrypted
            bytes.
        on_failure: Callback taking the format name and number of password attempts
            left.
        name: Name placed on the decrypted stream. None uses the decoded source path.

    Returns:
        The original stream, or a memory stream containing decrypted bytes. The caller
        must close it.
    """
    if set(mode) - {"r", "b", "t"} or isinstance(file, int) or not handle.seekable():
        return handle

    binary = "b" in mode
    try:
        # Inspect bytes so locale decoding never sees encrypted content.
        stream = handle if binary else handle.buffer
        kind = detect(stream.read(_FORMAT_PROBE_BYTES))
        handle.seek(0)
        if kind == "plain":
            return handle

        raw = stream.read(maximum_size + 1)
        if len(raw) > maximum_size:
            raise InvalidStore()
    except BaseException:
        handle.close()
        raise

    # Password input and retries run after the source handle has been released.
    handle.close()

    source = os.fsdecode(file)
    plain = b""
    for remaining in reversed(range(_PASSWORD_ATTEMPTS)):
        try:
            plain = decrypt(raw, source=source)
            break
        except AuthenticationFailed:
            on_failure(kind, remaining)
            if remaining == 0:
                raise

    buffer = io.BytesIO(plain)
    buffer.name = source if name is None else name

    return (
        buffer
        if binary
        else io.TextIOWrapper(buffer, encoding=encoding, errors=errors, newline=newline)
    )
