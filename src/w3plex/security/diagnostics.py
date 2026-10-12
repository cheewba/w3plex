"""Convert private async exceptions before ordinary service error reporting."""

import asyncio
from collections.abc import Awaitable, Callable
from functools import wraps

from .errors import SecurityError


def private_async[**P, T](
    function: Callable[P, Awaitable[T]],
) -> Callable[P, Awaitable[T]]:
    @wraps(function)
    async def wrapped(*args: P.args, **kwargs: P.kwargs) -> T:
        error = None
        cancelled = False
        try:
            return await function(*args, **kwargs)
        except asyncio.CancelledError:
            cancelled = True
        except SecurityError as exc:
            error = type(exc)
        except Exception:  # noqa: BLE001 -- never attach private exception locals/causes
            error = SecurityError
        if cancelled:
            raise asyncio.CancelledError()
        if error is None:
            raise SecurityError()
        raise error()

    return wrapped
