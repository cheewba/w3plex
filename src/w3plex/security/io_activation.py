"""Exclusive ownership of the explicitly activated built-in file opener."""

import builtins
import threading
from collections.abc import Callable
from typing import Any

from .errors import ActivationConflict

_LOCK = threading.RLock()
_ACTIVE: tuple[object, Callable[..., Any], Callable[..., Any]] | None = None


def activate(owner: object, opener: Callable[..., Any]) -> None:
    global _ACTIVE
    with _LOCK:
        if _ACTIVE is not None or getattr(
            getattr(builtins.open, "__self__", None), "_w3plex_security_context", False
        ):
            raise ActivationConflict()
        previous = builtins.open
        builtins.open = opener
        _ACTIVE = owner, opener, previous


def deactivate(owner: object) -> None:
    global _ACTIVE
    with _LOCK:
        if (
            _ACTIVE is None
            or _ACTIVE[0] is not owner
            or builtins.open is not _ACTIVE[1]
        ):
            raise ActivationConflict()
        builtins.open = _ACTIVE[2]
        _ACTIVE = None


def is_active(owner: object) -> bool:
    with _LOCK:
        return (
            _ACTIVE is not None and _ACTIVE[0] is owner and builtins.open is _ACTIVE[1]
        )
