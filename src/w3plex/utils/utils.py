from importlib import import_module
from typing import TYPE_CHECKING, Any, TypeVar

from lazyplex import CTX_APPLICATION, ContextScope, get_context
from w3ext import Chain

from ..constants import CONTEXT_CHAINS_KEY, CONTEXT_CONFIG_KEY

if TYPE_CHECKING:
    from ..core import Application


T = TypeVar("T")


def get_chains() -> dict[str, Chain]:
    """Return all loaded Chains."""
    return (get_context() or {}).get(CONTEXT_CHAINS_KEY) or {}


def get_config() -> dict[str, Any] | None:
    """Return current Application's config."""
    return (get_context() or {}).get(CONTEXT_CONFIG_KEY)


def get_application() -> "Application | None":
    """Return current Application."""
    return (get_context() or {}).get(CTX_APPLICATION)


def get_scope() -> ContextScope:
    ctx = get_context()
    return ctx.get_scope() if ctx is not None else ContextScope.application


def execute_on_complete(fn, *args, **kwargs):
    app = get_application()
    if app:
        app.add_complete_tasks(fn, *args, **kwargs)


def load_path(path: str):
    parts = path.split(":")
    loaded = import_module(parts[0])
    if len(parts) == 1:
        return loaded
    return getattr(loaded, parts[1])
