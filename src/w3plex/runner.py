#!/usr/bin/env python
import asyncio
import os
import sys
from contextlib import contextmanager
from functools import partial
from inspect import iscoroutinefunction, isfunction, iscoroutine
from typing import Any, Dict, Optional, Tuple, List

from lazyplex import Application as _Application
from lazyplex import create_context

from .constants import CONTEXT_CHAINS_KEY
from .utils import load_path
from .core import config_loader, ConfigTree
from .log import logger


APPLICATIONS_CFG_KEY = 'applications'
ACTIONS_CFG_KEY = 'actions'
LOGGING_DEFAULT_FORMAT = (
    "<green>{time:YYYY-MM-DD HH:mm:ss.SSS Z}</green> | "
    "<level>{level: <8}</level> | "
    "<cyan>{extra[application]}</cyan>:"
    "<cyan>{extra[action]}</cyan> | "
    "{extra[item_index]}. <cyan>{extra[item]}</cyan> - <level>{message}</level>"
)
LOGGING_DEFAULT_LEVEL = 'INFO'


class _AppProxy:
    def __init__(self, app, runner, cfg) -> None:
        self.__app = app
        self.__runner = runner
        self.__cfg = cfg

    @property
    def tree(self) -> Dict:
        return dict(self.__cfg)

    def __getattr__(self, name: str) -> Any:
        return getattr(self.__app, name)

    def __call__(self, *args, **kwargs):
        def filter_key(key):
            return (
                not key.startswith('__')
                and key not in [APPLICATIONS_CFG_KEY, ACTIONS_CFG_KEY]
            )

        a, kw = self.__app.update_args(
            [],
            {key: value for key, value in self.__cfg.items() if filter_key(key)},
            *args, **kwargs
        )
        return self.__runner.run_application(self.__app, *a, **kw)


class Runner:
    cfg: Optional[Dict] = None
    cfg_path: Optional[str] = None

    _tree: Optional[ConfigTree] = None

    def __init__(self, loop=None) -> None:
        self.loop: asyncio.AbstractEventLoop = loop or asyncio.get_event_loop()

    @property
    def is_initialized(self) -> bool:
        return self.cfg is not None

    @property
    def tree(self) -> ConfigTree:
        return self._tree

    async def resolve_value(self, value) -> Any:
        if (iscoroutinefunction(value)
                or isfunction(value)):
            value = value()
        if iscoroutine(value):
            value = await value
        return value

    async def resolve_args(self, app: _Application, *args, **kwargs) -> Tuple[Tuple, Dict]:
        a, kw = (
            [await self.resolve_value(arg) for arg in args],
            {key: (await self.resolve_value(value)) for key, value in kwargs.items()}
        )
        action_name, _ = app.action_from_args(*a, **kw)
        if action_name:
            app_tree = self._tree.get(APPLICATIONS_CFG_KEY).get(app.name).tree
            actions = app_tree.get(ACTIONS_CFG_KEY, {})
            action_cfg = dict(actions.get(action_name) or {})  # create a copy to modify it
            kw.update({key: (await self.resolve_value(value)) for key, value in action_cfg.items()})

        return a, kw

    def blocking_call(self, coro):
        if self.loop.is_running():
            # If the loop is running, we should schedule the coroutine as a new task
            future = asyncio.run_coroutine_threadsafe(coro, self.loop)
            # Wait for the result to be available (this is blocking)
            return future.result()
        else:
            # If the loop is not running, it's safe to run until the coroutine completes
            return self.loop.run_until_complete(coro)

    async def run_application(self, app: _Application, *args, **kwargs):
        with self._app_context(app):
            args, kwargs = await self.resolve_args(app, *args, **kwargs)
            await app(*args, **kwargs)

    async def init_application(self, cfg: Dict, path: str):
        def wrap_app(app):
            return _AppProxy(app, self, cfg)

        app_name = path.rsplit('.', 1)[-1]
        if (app_module := cfg.get('__init__')) is None:
            raise AttributeError(f"{app_name}: field `__init__` is required")
        apps = load_applications(app_module)
        if not len(apps):
            raise ValueError(f"No applications found for path '{app_module}'")
        (app := apps[0]).name = app_name
        return wrap_app(app)

    async def init(self, cfg, cfg_path):
        assert self.cfg is None, "Already initialized. Finalize first."

        # TODO: if there're more that one runner, will be conflict
        config_loader.add_node(r"^logging$")(self.init_loggers)
        config_loader.add_node(
            r"^applications\.[^.]+$", 'applications'
        )(self.init_application)

        self.cfg = cfg
        self.cfg_path = cfg_path
        self._tree = await config_loader.parse(cfg, cfg_path)

    def _parse_log_handler(self, config) -> Any:
        if (handler := config.pop('handler', None)) is not None:
            if isinstance(handler, str):
                return load_path(handler)
            return handler
        elif (filename := config.pop('file', None)) is not None:
            return os.path.join(os.path.dirname(self.cfg_path), filename)
        return sys.stderr

    def init_loggers(self, loggers: List[Dict], path: str):
        for log in loggers:
            log = log.copy()
            kwargs = {
                "sink": self._parse_log_handler(log),
                "format": LOGGING_DEFAULT_FORMAT,
                "level": LOGGING_DEFAULT_LEVEL,
            }
            kwargs.update(log)
            logger.add(**kwargs)
        return loggers

    async def finalize(self):
        assert self.cfg is not None, "Not initialized, to be finilized"

        self.cfg = None
        self.cfg_path = None

    @contextmanager
    def _app_context(self, app: _Application):
        # place w3plex import here to let main() function
        # add appropriate package to the PATH
        from w3plex.constants import CONTEXT_CONFIG_KEY, CONTEXT_EXTRAS_KEY

        cfg = dict(self.cfg)
        app_cfg = cfg.pop(APPLICATIONS_CFG_KEY).get(app.name)
        app_tree = self._tree.get(APPLICATIONS_CFG_KEY).get(app.name).tree
        with create_context({
            CONTEXT_CONFIG_KEY: dict(app_cfg),
            CONTEXT_EXTRAS_KEY: dict(cfg),
            CONTEXT_CHAINS_KEY: dict(
                chains if (chains := self.tree.get_collection('chains')) else {}
            ),
        }):
            # self._extend_app_actions(app, app_tree)
            yield app

    def _extend_app_actions(self, app: _Application, app_cfg: Dict):
        for action_name, action_cfg in app_cfg.get(ACTIONS_CFG_KEY, {}).items():
            action_cfg = dict(action_cfg or {})  # create a copy to modify it
            action_base = action_cfg.pop('action', None) or action_name
            app_action = app._actions.get(action_base)
            if app_action is None:
                raise ValueError(f"Application '{app.name}' doesn't have any action, "
                                f"that could be bound to config action '{action_name}'")
            app._actions[action_name] = partial(app_action, **action_cfg)


def load_applications(name: str):
    loaded = load_path(name)
    if isinstance(loaded, _Application):
        return [loaded]
    return [attr for attr in vars(loaded).values()
            if isinstance(attr, _Application)]
