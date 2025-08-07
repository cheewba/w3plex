from dataclasses import dataclass
from typing import Generic, TypeVar, Callable, overload, Any

from lazyplex import (
    Application as _Application,
    ApplicationAction as _ApplicationAction,
    application as _application,
)
from ..constants import CONTEXT_CONFIG_KEY, CONTEXT_LOGGER_KEY
from ..exceptions import SkipItem, W3PlexError
from ..logging import logger
from ..utils import get_context


T = TypeVar('T')


class ApplicationAction(_ApplicationAction):
    async def get_item_context(self, *args, **kwargs):
        ctx = await super().get_item_context(*args, **kwargs)
        logger = get_context()[CONTEXT_LOGGER_KEY]
        logger = logger.bind(**{
            "item": ctx[self.context_key],
            "item_index": ctx[f"{self.context_key}_index"]
        })

        return {
            CONTEXT_LOGGER_KEY: logger,
            **ctx
        }

    async def process_item(self, item: Any, *args, **kwargs):
        try:
            if isinstance(item, ActionData):
                kwargs['index'] = item.index
                item = item.item
            return await super().process_item(item, *args, **kwargs)
        except SkipItem as e:
            return e.result
        except W3PlexError as e:
            logger.error(e)
        except Exception as e:
            logger.exception(e)
            raise


class Application(_Application):
    action_class = ApplicationAction

    async def update_application_context(self, ctx):
        await super().update_application_context(ctx)
        _logger = logger.bind(
            application=self.name,
            application_config=ctx.get(CONTEXT_CONFIG_KEY),
        )
        ctx[CONTEXT_LOGGER_KEY] = _logger


@dataclass
class ActionData(Generic[T]):
    item: T
    index: int


@overload
def application(fn: Callable) -> Application: ...
@overload
def application(*, return_exceptions: bool = False) -> Callable[[Callable], Application]: ...

def application(*args, **kwargs):
    """ Wrapper around ``lazyplex.application`` that accepts function as argument only.

        Threre's no need to pass name of the application, since
        it's taken from the config file.
    """
    kwargs['application_class'] = Application
    if args and isinstance(args[0], Callable):
        return _application(**kwargs)(args[0])
    return _application(*args, **kwargs)