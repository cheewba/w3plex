"""Convert private async exceptions before ordinary service error reporting."""

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
    """Use only trusted fixed-code classes; never inspect an instance message."""
    for kind in _SAFE_ERRORS:
        if type(error) is kind:
            return kind
    return SecurityError


def private_async[**P, T](
    function: Callable[P, Awaitable[T]],
) -> Callable[P, CoroutineType[Any, Any, T]]:
    @wraps(function)
    async def wrapped(*args: P.args, **kwargs: P.kwargs) -> T:
        error = None
        cancelled = False
        try:
            return await function(*args, **kwargs)
        except asyncio.CancelledError:
            cancelled = True
        except SecurityError as exc:
            error = safe_error_type(exc)
        except Exception:  # noqa: BLE001 -- never attach private exception locals/causes
            error = SecurityError
        del args, kwargs
        if cancelled:
            raise asyncio.CancelledError()
        if error is None:
            raise SecurityError()
        raise error()

    return wrapped
