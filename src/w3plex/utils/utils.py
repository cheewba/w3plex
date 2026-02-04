from importlib import import_module
from typing import Optional, Dict, TypeVar, Any, TYPE_CHECKING

from w3ext import Chain
from lazyplex import get_context, CTX_APPLICATION, ContextScope

from ..constants import (
    CONTEXT_CHAINS_KEY, CONTEXT_CONFIG_KEY
)
if TYPE_CHECKING:
    from ..core import Application


T = TypeVar("T")



def get_chains() -> Optional[Dict[str, Chain]]:
    """ Return all loaded Chains. """
    return get_context().get(CONTEXT_CHAINS_KEY)


def get_config() -> Optional[Dict[str, Any]]:
    """ Return current Application's config. """
    return get_context().get(CONTEXT_CONFIG_KEY)


def get_application() -> "Application":
    """ Return current Application. """
    return get_context().get(CTX_APPLICATION)


def get_scope() -> ContextScope:
    ctx = get_context()
    return ctx.get_scope()


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
