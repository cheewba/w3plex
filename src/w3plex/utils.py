from typing import List, Optional, Dict, Callable, TypeVar, Any

from w3ext import Account, Chain
from lazyplex import get_context, CTX_APPLICATION

from .constants import CONTEXT_CHAINS_KEY, CONTEXT_CONFIG_KEY

T = TypeVar("T")

async def load_from_file(filename: str, process: Optional[Callable[[T, int], T]] = None) -> List[T]:
    with open(filename, 'r', encoding='utf-8-sig') as file:
        process = process or (lambda item, i: item);
        return [process(line.strip(), i)
                for i, line in enumerate(file) if line.strip()]


def get_account() -> Optional[Account]:
    """ Return Account for the current action. """
    ctx = get_context()
    app = ctx.get(CTX_APPLICATION)

    return ctx.get(app.context_key)


def get_chains() -> Optional[Dict[str, Chain]]:
    """ Return all loaded Chains. """
    return get_context().get(CONTEXT_CHAINS_KEY)


def get_config() -> Optional[Dict[str, Any]]:
    """ Return current Application's config. """
    return get_context().get(CONTEXT_CONFIG_KEY)
