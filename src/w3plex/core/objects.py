from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, overload

from lazyplex import (
    Application as _Application,
    ApplicationAction as _ApplicationAction,
    application as _application,
)

from ..config import Lazy
from ..constants import CONTEXT_CONFIG_KEY, CONTEXT_LOGGER_KEY
from ..exceptions import SkipItem, W3PlexError
from ..log import logger
from ..utils import get_context


class ApplicationAction(_ApplicationAction):
    """Prepare action arguments and add a logger with details about each item."""

    async def _process_action(self, item: Any, action: Any):
        # lazyplex treats every iterable result as a collection of actions.
        # Strings and bytes are complete values, not character-level actions.
        if isinstance(action, (str, bytes)):
            return action
        return await super()._process_action(item, action)

    async def get_item_context(self, *args, **kwargs):
        """Add a logger with item details to the action context."""
        ctx = await super().get_item_context(*args, **kwargs)
        logger = get_context()[CONTEXT_LOGGER_KEY]
        logger = logger.bind(
            item=ctx[self.context_key], item_index=ctx[f"{self.context_key}_index"]
        )

        return {CONTEXT_LOGGER_KEY: logger, **ctx}

    async def process_item(self, item: Any, *args, **kwargs):
        """Process an item using its ActionData index and any SkipItem result."""
        try:
            if isinstance(item, ActionData):
                kwargs["index"] = item.index
                item = item.item
            return await super().process_item(item, *args, **kwargs)
        except SkipItem as e:
            return e.result
        except W3PlexError as e:
            logger.error(e)
            raise
        except Exception as e:
            logger.exception(e)
            raise

    async def parse_args(
        self, *args, **kwargs
    ) -> tuple[tuple[Any, ...], dict[str, Any]]:
        """Read Lazy values that should run now, including values inside containers."""

        async def resolve_value(value: Any) -> Any:
            if isinstance(value, dict):
                return {
                    key: await resolve_value(subvalue)
                    for key, subvalue in value.items()
                }
            elif isinstance(value, (list, tuple, set)):
                resolved = [await resolve_value(item) for item in value]
                return type(value)(resolved)
            elif isinstance(value, Lazy) and not value.as_lazy:
                return await value()
            return value

        args = await resolve_value(args)
        kwargs = await resolve_value(kwargs)

        return await super().parse_args(*args, **kwargs)


class Application(_Application):
    """Add configured logging and Lazy argument handling to a lazyplex application."""

    action_class = ApplicationAction

    async def process_action_data(self, action, data, counter=None, kwargs=None):
        """Process text or bytes as one item when protected_items is disabled."""
        if isinstance(data, (str, bytes)) and not self.protected_items:
            data = [data]
        return await super().process_action_data(action, data, counter, kwargs)

    async def update_application_context(self, ctx):
        """Add a logger with application details to its context."""
        await super().update_application_context(ctx)
        _logger = logger.bind(
            application=self.name,
            application_config=ctx.get(CONTEXT_CONFIG_KEY),
        )
        ctx[CONTEXT_LOGGER_KEY] = _logger
        return ctx


@dataclass
class ActionData[T]:
    """Keep an action item together with its processing index."""

    item: T
    index: int


@overload
def application(fn: Callable) -> Application: ...
@overload
def application(
    *, return_exceptions: bool = False
) -> Callable[[Callable], Application]: ...


def application(*args, **kwargs):
    """Create a w3plex application from a function.

    The config supplies the application name, so the decorator does not need one.
    """
    kwargs["application_class"] = Application
    if args and isinstance(args[0], Callable):
        return _application(**kwargs)(args[0])
    return _application(*args, **kwargs)
