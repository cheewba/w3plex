"""Report safe error codes instead of private exception details."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from functools import wraps
from types import CoroutineType
from typing import Any

from .errors import (
    ActivationConflict,
    AuthenticationFailed,
    InteractionRequired,
    InvalidStore,
    PermissionDenied,
    SecurityError,
    UnsupportedProtection,
)
from .storage import StoreChanged, UnsafeStorage, WriterBusy

_SAFE_ERRORS = {
    SecurityError,
    ActivationConflict,
    AuthenticationFailed,
    InteractionRequired,
    InvalidStore,
    PermissionDenied,
    UnsupportedProtection,
    StoreChanged,
    UnsafeStorage,
    WriterBusy,
}


def safe_error_type(error: BaseException) -> type[SecurityError]:
    """Choose a known error type without reading its private message.

    Args:
        error: The caught exception to classify.

    Returns:
        The same error class if it is allowed, otherwise SecurityError.
    """
    for kind in _SAFE_ERRORS:
        if type(error) is kind:
            return kind
    return SecurityError


def private_call[T](function: Callable[[], T]) -> T:
    """Call a function and keep private error details out of its result.

    Failures become known security errors without the original exception chain.
    Traceback frames still belong to trusted code; do not log their local variables.

    Args:
        function: A function taking no arguments. It may read private data.

    Returns:
        The value returned by function.
    """
    try:
        return function()
    except Exception as exc:  # noqa: BLE001 -- private library errors are never forwarded
        error = safe_error_type(exc)
    del function
    # Raise here so the original exception and its private data are not linked.
    raise error()


def private_async[**P, T](
    function: Callable[P, Awaitable[T]],
) -> Callable[P, CoroutineType[Any, Any, T]]:
    """Wrap an async function so its errors do not expose private details.

    Args:
        function: The async function to wrap. Its arguments and return value are
            unchanged.

    Returns:
        An async wrapper that reports known error types and removes private messages
        from cancellation errors.
    """

    @wraps(function)
    async def wrapped(*args: P.args, **kwargs: P.kwargs) -> T:
        error: type[BaseException]
        try:
            return await function(*args, **kwargs)
        except asyncio.CancelledError:
            error = asyncio.CancelledError
        except Exception as exc:  # noqa: BLE001 -- never attach private exception locals/causes
            error = safe_error_type(exc)
        del args, kwargs
        raise error()

    return wrapped
