import copy
import sys
from collections import defaultdict

from loguru import logger as _logger

from . import get_context
from .constants import CONTEXT_LOGGER_KEY

__all__ = ["logger"]


class Logger:
    def __init__(self, logger):
        self._logger = logger

    def __getattribute__(self, name):
        if name == '_logger':
            return super().__getattribute__(name)

        ctx = get_context() or {}
        return getattr(ctx[CONTEXT_LOGGER_KEY] if CONTEXT_LOGGER_KEY in ctx else self._logger, name)


# to be able to copy loguru logger, all handlers should be removed
_logger.remove()
logger = Logger(copy.deepcopy(_logger).patch(
    lambda record: record.__setitem__(
        "extra",
        defaultdict(str, record["extra"])
    ),
))
# setup default logger to the loguru again
_logger.add(sys.stderr)