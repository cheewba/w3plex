"""Allow one context at a time to control builtins.open."""

import builtins
import threading
from collections.abc import Callable
from typing import Any

from .errors import ActivationConflict

_LOCK = threading.RLock()
_ACTIVE: tuple[object, Callable[..., Any], Callable[..., Any]] | None = None


def activate(owner: object, opener: Callable[..., Any]) -> None:
    """Install a file opener and save the previous one.

    Only one owner can be active at a time.

    Args:
        owner: The object that will control the installed opener.
        opener: An open-compatible function to install as builtins.open.

    Returns:
        None.
    """
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
    """Restore the previous file opener.

    The owner and installed opener must still match.

    Args:
        owner: The object that installed the current opener.

    Returns:
        None.
    """
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
    """Check whether an owner still controls the file opener.

    Args:
        owner: The object whose ownership should be checked.

    Returns:
        True if this owner still controls the installed opener.
    """
    with _LOCK:
        return (
            _ACTIVE is not None and _ACTIVE[0] is owner and builtins.open is _ACTIVE[1]
        )
