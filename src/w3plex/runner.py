import asyncio
import os
import sys
from contextlib import contextmanager
from copy import deepcopy
from inspect import iscoroutine, iscoroutinefunction, isfunction
from typing import Any

from lazyplex import Application as _Application, create_context

from .config import ConfigTree, Lazy, config_loader
from .config.config import populate_config_tree
from .constants import (
    ACTIONS_CFG_KEY,
    APPLICATIONS_CFG_KEY,
    CONTEXT_CHAINS_KEY,
    CONTEXT_CONFIG_KEY,
    CONTEXT_EXTRAS_KEY,
    CONTEXT_VARS_KEY,
    VARS_COLLECTION,
)
from .log import logger
from .security.file_opener import DefaultFileOpener
from .utils import load_path
from .utils.loader import FileOpener, get_file_opener, using_file_opener

LOGGING_DEFAULT_FORMAT = (
    "<green>{time:YYYY-MM-DD HH:mm:ss.SSS Z}</green> | "
    "<level>{level: <8}</level> | "
    "<cyan>{extra[application]}</cyan>:"
    "<cyan>{extra[action]}</cyan> | "
    "{extra[item_index]}. <cyan>{extra[item]}</cyan> - <level>{message}</level>"
)
LOGGING_DEFAULT_LEVEL = "INFO"


class _AppProxy:
    def __init__(self, app, runner, cfg) -> None:
        self.__app = app
        self.__runner = runner
        self.__cfg = cfg

    @property
    def tree(self) -> dict:
        """Return a shallow copy of this application's configuration."""
        return dict(self.__cfg)

    def __getattr__(self, name: str) -> Any:
        return getattr(self.__app, name)

    def __call__(self, *args, **kwargs):
        def filter_key(key):
            return not key.startswith("__") and key not in [
                APPLICATIONS_CFG_KEY,
                ACTIONS_CFG_KEY,
            ]

        defaults = {key: value for key, value in self.__cfg.items() if filter_key(key)}
        a, kw = self.__app.update_args(
            [],
            defaults,
            *args,
            **kwargs,
        )
        action_name, _ = self.__app.action_from_args(*a, **kw)
        action_cfg = dict(self.__cfg.get(ACTIONS_CFG_KEY, {}).get(action_name) or {})
        canonical = action_cfg.pop("action", action_name)
        defaults.update(action_cfg)
        a, kw = self.__app.update_args([], defaults, *args, **kwargs)
        if canonical:
            a, kw = self.__app.update_args(a, kw, action=canonical)
            if self.__app.action_from_args(*a, **kw)[1] is None:
                raise ValueError(f"Unknown action '{canonical}' for {self.__app.name}")
        return self.__runner.run_application(self.__app, *a, **kw)


class Runner:
    """Create configured applications and run them with their context and resources."""

    cfg: dict | None = None
    cfg_path: str | None = None

    _tree: ConfigTree | None = None

    def __init__(self, loop=None) -> None:
        """Bind an existing event loop or create one for blocking calls."""
        if loop is None:
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
        self.loop: asyncio.AbstractEventLoop = loop
        self._log_sinks: list[int] = []
        self._file_opener: FileOpener | None = None
        self._owned_file_opener: DefaultFileOpener | None = None
        self._initializing_tree: ConfigTree | None = None
        self._cleanup: asyncio.Task[None] | None = None

    @property
    def is_initialized(self) -> bool:
        """Return whether this runner has configuration."""
        return self.cfg is not None

    @property
    def tree(self) -> ConfigTree:
        """Return the config tree. Initialization must have completed first."""
        if self._tree is None:
            raise RuntimeError("Runner is not initialized")
        return self._tree

    async def resolve_value(self, value) -> Any:
        """Read or call a value, leaving Lazy values for the action context."""
        if isinstance(value, Lazy):
            # Lazy should be resolved on action level,
            # when action context is defined
            return value
        if iscoroutinefunction(value) or isfunction(value):
            value = value()
        if iscoroutine(value):
            value = await value
        return value

    async def resolve_args(
        self, app: _Application, *args, **kwargs
    ) -> tuple[list[Any], dict[str, Any]]:
        """Prepare positional and keyword arguments before calling an application."""
        a, kw = (
            [await self.resolve_value(arg) for arg in args],
            {key: (await self.resolve_value(value)) for key, value in kwargs.items()},
        )
        return a, kw

    def blocking_call(self, coro):
        """Run a coroutine on the runner's loop and block for its result."""
        if self.loop.is_running():
            try:
                current_loop = asyncio.get_running_loop()
            except RuntimeError:
                current_loop = None
            if current_loop is self.loop:
                coro.close()
                raise RuntimeError(
                    "Use await when calling from the runner's event loop"
                )
            # If the loop is running, we should schedule the coroutine as a new task
            future = asyncio.run_coroutine_threadsafe(coro, self.loop)
            # Wait for the result to be available (this is blocking)
            return future.result()
        else:
            # If the loop is not running, it's safe to run until the coroutine completes
            return self.loop.run_until_complete(coro)

    async def run_application(self, app: _Application, *args, **kwargs):
        """Resolve arguments and invoke an application within its runner context."""
        with self._app_context(app):
            args, kwargs = await self.resolve_args(app, *args, **kwargs)
            return await app(*args, **kwargs)

    async def init_application(self, cfg: dict, path: str):
        """Load an application and prepare its configured arguments for this runner."""

        def wrap_app(app):
            return _AppProxy(app, self, cfg)

        app_name = path.rsplit(".", 1)[-1]
        if (app_module := cfg.get("__init__")) is None:
            raise AttributeError(f"{app_name}: field `__init__` is required")
        apps = load_applications(app_module)
        if not len(apps):
            raise ValueError(f"No applications found for path '{app_module}'")
        source = apps[0]
        # lazyplex's __getattr__ depends on initialized state, so copy.copy()
        # cannot reconstruct it. Copy the initialized state directly.
        app = object.__new__(type(source))
        app.__dict__.update(source.__dict__)
        app.name = app_name
        return wrap_app(app)

    async def init(self, cfg: dict, cfg_path: str):
        """Build the config tree and prepare this runner.

        The tree owns its configured resources. Failed initialization is cleaned up
        automatically, including resources created before the failure.

        Readers inherit the current file opener. Without one, this runner creates a
        standalone opener and closes it during finalize().

        Args:
            cfg: Config data containing applications and other configured objects.
            cfg_path: Config filename used to resolve relative paths.

        Returns:
            None.
        """
        if self._cleanup is not None:
            await asyncio.shield(self._cleanup)
            self._cleanup = None
        assert self.cfg is None, "Already initialized. Finalize first."

        loader = config_loader.clone()
        loader.add_node(r"^logging$")(self.init_loggers)
        loader.add_node(r"^applications\.[^.]+$", "applications")(self.init_application)

        self.cfg = deepcopy(cfg)
        self.cfg_path = cfg_path
        tree = self._initializing_tree = ConfigTree()
        construction_completed = False
        try:
            self._file_opener = get_file_opener()
            if self._file_opener is None:
                self._owned_file_opener = DefaultFileOpener()
                self._file_opener = self._owned_file_opener
            with using_file_opener(self._file_opener):
                await populate_config_tree(tree, cfg, cfg_path, loader=loader)
            construction_completed = True
            task = asyncio.current_task()
            if task is not None and task.cancelling():
                raise asyncio.CancelledError()
            self._tree = tree
            self._initializing_tree = None
        except BaseException as error:
            task = asyncio.current_task()
            if (
                isinstance(error, asyncio.CancelledError)
                and task is not None
                and task.cancelling()
                and not construction_completed
            ):
                # The tree's cleanup may still be running after a cancelled wait.
                # Retain it for finalize() or the next init(), without another wait
                # in this already cancelled caller.
                self.cfg = None
                self._start_cleanup()
                raise
            await self.finalize()
            raise

    def _parse_log_handler(self, config) -> Any:
        if (handler := config.pop("handler", None)) is not None:
            if isinstance(handler, str):
                return load_path(handler)
            return handler
        elif (filename := config.pop("file", None)) is not None:
            if self.cfg_path is None:
                raise RuntimeError("Runner config path is not set")
            return os.path.join(os.path.dirname(self.cfg_path), filename)
        return sys.stderr

    def init_loggers(self, loggers: list[dict], path: str):
        """Create log outputs and keep their IDs so finalize() can remove them."""
        for log in loggers:
            log = log.copy()
            is_file = "file" in log
            kwargs = {
                "sink": self._parse_log_handler(log),
                "format": LOGGING_DEFAULT_FORMAT,
                "level": LOGGING_DEFAULT_LEVEL,
                "colorize": not is_file,
            }
            kwargs.update(log)
            self._log_sinks.append(logger.add(**kwargs))
        return loggers

    async def finalize(self):
        """Join owned cleanup without cancelling it when a waiter is cancelled."""
        await asyncio.shield(self._start_cleanup())

    def _start_cleanup(self) -> asyncio.Task[None]:
        if self._cleanup is None:
            self._cleanup = asyncio.create_task(self._finalize())
            self._cleanup.add_done_callback(
                lambda task: None if task.cancelled() else task.exception()
            )
        return self._cleanup

    async def _finalize(self) -> None:
        tree = self._tree if self._tree is not None else self._initializing_tree
        try:
            try:
                if tree is not None:
                    await tree.close()
            finally:
                if self._owned_file_opener is not None:
                    self._owned_file_opener.close()
        finally:
            self._tree = None
            self._initializing_tree = None
            self.cfg = None
            self.cfg_path = None
            self._file_opener = None
            self._owned_file_opener = None
            for sink in self._log_sinks:
                logger.remove(sink)
            self._log_sinks.clear()

    @contextmanager
    def _app_context(self, app: _Application):
        if self.cfg is None:
            raise RuntimeError("Runner is not initialized")
        cfg = dict(self.cfg)
        app_cfg = cfg.pop(APPLICATIONS_CFG_KEY).get(app.name)
        with (
            using_file_opener(self._file_opener),
            create_context(
                {
                    CONTEXT_CONFIG_KEY: dict(app_cfg),
                    CONTEXT_EXTRAS_KEY: dict(cfg),
                    CONTEXT_CHAINS_KEY: dict(
                        chains if (chains := self.tree.get_collection("chains")) else {}
                    ),
                    CONTEXT_VARS_KEY: self.tree.get_collection(VARS_COLLECTION),
                }
            ),
        ):
            yield app


def load_applications(name: str):
    """Load one application, or find the applications defined in a module."""
    loaded = load_path(name)
    if isinstance(loaded, _Application):
        return [loaded]
    return [attr for attr in vars(loaded).values() if isinstance(attr, _Application)]
