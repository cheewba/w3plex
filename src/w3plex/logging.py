import copy
import logging
import sys
import warnings
from collections import defaultdict

from loguru import logger as _logger

from . import get_context
from .constants import CONTEXT_LOGGER_KEY

__all__ = ["logger"]

# 1) Make stdlib logging records flow into Loguru
class InterceptHandler(logging.Handler):
    def emit(self, record):
        try:
            level = logger.level(record.levelname).name
        except Exception:
            level = record.levelno
        logger.opt(depth=6, exception=record.exc_info).log(level, record.getMessage())


class Logger:
    def __init__(self, logger):
        self._logger = logger

    def __getattribute__(self, name):
        if name == '_logger':
            return super().__getattribute__(name)

        ctx = get_context() or {}
        return getattr(ctx[CONTEXT_LOGGER_KEY] if CONTEXT_LOGGER_KEY in ctx else self._logger, name)

root = logging.getLogger()
root.handlers = [InterceptHandler()]
root.setLevel(logging.NOTSET)

# 2) Forward Python warnings to stdlib logging ('py.warnings' logger)
logging.captureWarnings(True)

# 3) Actually enable DeprecationWarning (it is ignored by default)
warnings.simplefilter("default", DeprecationWarning)

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