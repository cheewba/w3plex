import copy
import logging
import sys
import warnings
import html
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

        try:
            logger.opt(depth=6, exception=record.exc_info).log(level, record.getMessage())
        except Exception:
            logger.opt(depth=6, exception=record.exc_info).log(
                level, html.escape(record.getMessage())
            )


class Logger:
    def __init__(self, logger):
        self._logger = logger.opt(colors=True)

    def __getattribute__(self, name):
        try:
            # Prefer our own attributes/methods so we can wrap calls safely
            return super().__getattribute__(name)
        except AttributeError:
            return getattr(self._delegate(), name)

    # helpers
    def _delegate(self):
        return (get_context() or {}).get(CONTEXT_LOGGER_KEY) or self._logger

    @staticmethod
    def _escape_html_value(v):
        try:
            s = str(v)
        except Exception:
            try:
                s = repr(v)
            except Exception:
                s = "<unrepresentable>"
        try:
            return html.escape(s, quote=False)
        except Exception:
            return s

    def _safe_invoke(self, call, msg, *args, **kwargs):
        # 1) Primary attempt: call with original values
        try:
            return call(msg, *args, **kwargs)
        except Exception:
            pass
        # 2) Fallback: HTML-escape values and retry once
        try:
            safe_msg = self._escape_html_value(msg)
            safe_args = tuple(self._escape_html_value(a) for a in args)
            safe_kwargs = {}
            for k, v in kwargs.items():
                if k in ('exc_info', 'stack_info'):
                    safe_kwargs[k] = v
                else:
                    safe_kwargs[k] = self._escape_html_value(v)
            return call(safe_msg, *safe_args, **safe_kwargs)
        except Exception:
            pass
        # 3) Final failsafe: minimal stderr line
        try:
            sys.stderr.write(f"[LOGGING-FAILSAFE] {self._escape_html_value(msg)}\n")
        except Exception:
            pass

    def _safe_log(self, method_name, msg, *args, **kwargs):
        return self._safe_invoke(getattr(self._delegate(), method_name), msg, *args, **kwargs)

    def setLevel(self, level):
        """
        Set the logging level of this logger.  level must be an int or a str.
        """
        ...

    def debug(self, msg, *args, **kwargs):
        """
        Log 'msg % args' with severity 'DEBUG'.
        """
        return self._safe_log("debug", msg, *args, **kwargs)

    def info(self, msg, *args, **kwargs):
        """
        Log 'msg % args' with severity 'INFO'.
        """
        return self._safe_log("info", msg, *args, **kwargs)

    def warning(self, msg, *args, **kwargs):
        """
        Log 'msg % args' with severity 'WARNING'.
        """
        return self._safe_log("warning", msg, *args, **kwargs)

    def warn(self, msg, *args, **kwargs):
        """
        Alias for warning().
        """
        return self._safe_log("warning", msg, *args, **kwargs)

    def error(self, msg, *args, **kwargs):
        """
        Log 'msg % args' with severity 'ERROR'.
        """
        return self._safe_log("error", msg, *args, **kwargs)

    def exception(self, msg, *args, exc_info=True, **kwargs):
        """
        Convenience method for logging an ERROR with exception information.
        """
        kwargs.setdefault("exc_info", exc_info)
        return self._safe_log("error", msg, *args, **kwargs)

    def critical(self, msg, *args, **kwargs):
        """
        Log 'msg % args' with severity 'CRITICAL'.
        """
        return self._safe_log("critical", msg, *args, **kwargs)

    def fatal(self, msg, *args, **kwargs):
        """
        Alias for critical().
        """
        return self._safe_log("critical", msg, *args, **kwargs)

    def log(self, level, msg, *args, **kwargs):
        """
        Log 'msg % args' with the integer or string severity 'level'.
        """
        log_method = getattr(self._delegate(), "log")
        return self._safe_invoke(lambda m, *a, **kw: log_method(level, m, *a, **kw), msg, *args, **kwargs)


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