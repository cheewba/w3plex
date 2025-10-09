import copy
import logging
import sys
import warnings
from collections import defaultdict

from loguru import logger as _logger

from . import get_context
from .constants import CONTEXT_LOGGER_KEY

__all__ = ["logger"]


class _Logger(logging.Logger):
    @property
    def handlers(self):
        return []

    @handlers.setter
    def handlers(self, value):
        pass

    @property
    def propagate(self):
        return True

    @propagate.setter
    def propagate(self, value):
        pass

    def addHandler(self, h):
        pass


class _RootLogger(logging.RootLogger):
    @property
    def handlers(self):
        handlers = getattr(self, '_hdl', None)
        if handlers is None:
            handlers = [InterceptHandler()]
            setattr(self, '_hdl', handlers)
        return handlers

    @handlers.setter
    def handlers(self, value):
        pass

    def addHandler(self, h):
        pass


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
        self._logger = logger.opt(colors=True)

    def __getattribute__(self, name):
        if name == '_logger':
            return super().__getattribute__(name)

        ctx = get_context() or {}
        return getattr(ctx[CONTEXT_LOGGER_KEY] if CONTEXT_LOGGER_KEY in ctx else self._logger, name)

    def setLevel(self, level):
        """
        Set the logging level of this logger.  level must be an int or a str.
        """
        ...

    def debug(self, msg, *args, **kwargs):
        """
        Log 'msg % args' with severity 'DEBUG'.

        To pass exception information, use the keyword argument exc_info with
        a true value, e.g.

        logger.debug("Houston, we have a %s", "thorny problem", exc_info=True)
        """
        ...

    def info(self, msg, *args, **kwargs):
        """
        Log 'msg % args' with severity 'INFO'.

        To pass exception information, use the keyword argument exc_info with
        a true value, e.g.

        logger.info("Houston, we have a %s", "notable problem", exc_info=True)
        """
        ...

    def warning(self, msg, *args, **kwargs):
        """
        Log 'msg % args' with severity 'WARNING'.

        To pass exception information, use the keyword argument exc_info with
        a true value, e.g.

        logger.warning("Houston, we have a %s", "bit of a problem", exc_info=True)
        """
        ...

    def warn(self, msg, *args, **kwargs):
        ...

    def error(self, msg, *args, **kwargs):
        """
        Log 'msg % args' with severity 'ERROR'.

        To pass exception information, use the keyword argument exc_info with
        a true value, e.g.

        logger.error("Houston, we have a %s", "major problem", exc_info=True)
        """
        ...

    def exception(self, msg, *args, exc_info=True, **kwargs):
        """
        Convenience method for logging an ERROR with exception information.
        """
        self.error(msg, *args, exc_info=exc_info, **kwargs)

    def critical(self, msg, *args, **kwargs):
        """
        Log 'msg % args' with severity 'CRITICAL'.

        To pass exception information, use the keyword argument exc_info with
        a true value, e.g.

        logger.critical("Houston, we have a %s", "major disaster", exc_info=True)
        """
        ...

    def fatal(self, msg, *args, **kwargs):
        """
        Don't use this method, use critical() instead.
        """
        ...

    def log(self, level, msg, *args, **kwargs):
        """
        Log 'msg % args' with the integer severity 'level'.

        To pass exception information, use the keyword argument exc_info with
        a true value, e.g.

        logger.log(level, "We have a %s", "mysterious problem", exc_info=True)
        """
        ...


def monkey_match_standard_logging():
    _patch_root_logger()
    _patch_loggers()


def _patch_loggers():
    MY_LOGGER_CLASS = _Logger

    # lock the setter
    _orig_setLoggerClass = logging.setLoggerClass
    def _locked_setLoggerClass(cls):
        # allow re-setting to the same class; ignore anything else
        if cls is MY_LOGGER_CLASS:
            return _orig_setLoggerClass(cls)
        # optionally log a warning here
        return
    logging.setLoggerClass = _locked_setLoggerClass

    # pin the current manager too
    _orig_setLoggerClass(MY_LOGGER_CLASS)
    logging.root.manager.loggerClass = MY_LOGGER_CLASS


def _patch_root_logger():
    new_root = _RootLogger(logging.NOTSET)
    new_root.setLevel(logging.NOTSET)

    # swap globals used by logging internals
    logging.root = new_root
    logging.Logger.root = new_root
    logging.Logger.manager = logging.Manager(new_root)


monkey_match_standard_logging()

# Forward Python warnings to stdlib logging ('py.warnings' logger)
logging.captureWarnings(True)

# Actually enable DeprecationWarning (it is ignored by default)
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
_logger.add(sys.stderr, level="INFO", enqueue=True,
            backtrace=False, diagnose=False, colorize=True)