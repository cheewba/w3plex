#!/usr/bin/env python
import argparse
import asyncio
import io
import os
import signal
import sys
import textwrap
from contextlib import contextmanager
from functools import partial
from inspect import iscoroutinefunction, isfunction, iscoroutine
from types import MethodType
from typing import Any, Dict, Optional, Tuple, List

from dotenv import load_dotenv
from lazyplex import Application as _Application
from lazyplex import create_context
from ptpython.repl import embed
from rich import print
from rich.text import Text
from ruamel.yaml import (
    dump as yaml_dump,
    load as yaml_load,
)

from .constants import CONTEXT_CHAINS_KEY, CONTEXT_SERVICES_KEY
from .utils import AttrDict, load_path
from .utils.loader import Loader
from .yaml import Dumper, Include, Loader as YamlLoader
from .core import config_loader, ConfigTree
from .logging import logger


load_dotenv()

CHAINS_CONFIG_NAME = 'chains.yaml'
DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(__file__), 'w3plex.yaml')
APPLICATIONS_CFG_KEY = 'applications'
ACTIONS_CFG_KEY = 'actions'
LOGGING_CFG_KEY = 'logging'
LOGGING_DEFAULT_FORMAT = (
    "<green>{time:YYYY-MM-DD HH:mm:ss.SSS Z}</green> | "
    "<level>{level: <8}</level> | "
    "<cyan>{extra[application]}</cyan>:"
    "<cyan>{extra[action]}</cyan> | "
    "{extra[item_index]}. <cyan>{extra[item]}</cyan> - <level>{message}</level>"
)
LOGGING_DEFAULT_LEVEL = 'INFO'


def _get_base_args_parse(*args, **kwargs) -> Tuple[argparse.ArgumentParser]:
    parser = argparse.ArgumentParser(*args, **kwargs)
    parser.add_argument('--config', '-c', help='run using w3plex config file', default='w3plex.yaml')

    return parser


def process_args():
    cfg_parser = _get_base_args_parse(add_help=False)
    cfg_parser.add_argument('kwargs', nargs="*")
    cfg_args, _ = cfg_parser.parse_known_args()

    cfg_path = os.path.abspath(cfg_args.config)
    cfg = load_config(cfg_path) if os.path.exists(cfg_path) else None

    parser = _get_base_args_parse()
    actions = parser.add_subparsers(title="w3plex actions", required=False)
    init = actions.add_parser('init', description="Initialize a new config")
    init.set_defaults(func=init_cmd)

    if cfg is not None:
        shell = actions.add_parser('shell', description="Start w3ext shell for the current config")
        shell.set_defaults(func=partial(run_shell_cmd, cfg=cfg, cfg_path=cfg_path))

        for app_name in cfg.get(APPLICATIONS_CFG_KEY, {}).keys():
            cmd = actions.add_parser(app_name, description=f"Run `{app_name}` application")
            cmd.add_argument("args", nargs='*', default=[], help="Single value or Key-value pairs separated by a comma. (e.g., value1 key2=value2)")
            cmd.set_defaults(func=partial(run_app_cmd, name=app_name, cfg=cfg,
                                          cfg_path=cfg_path))

    args = parser.parse_args(" ".join(sys.argv[1:]).split(" "))

    func = getattr(args, 'func', None)
    if func is not None:
        return func(args)


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


class Shell:
    def __init__(self, args, cfg, cfg_path) -> None:
        self.args = args
        self.cfg = cfg
        self.cfg_path = cfg_path
        self.loop = asyncio.get_event_loop()
        self.runner = Runner(self.loop)

        self._active_tasks: set[asyncio.Future] = set()
        self._main_task = None

    def _term_active_tasks(self):
        for task in self._active_tasks:
            task.cancel()

    def __call__(self) -> Any:
        async def task():
            await self.runner.init(self.cfg, self.cfg_path)
            try:
                await self._run_shell()
            finally:
                await self.runner.finalize()

        self.loop.add_signal_handler(signal.SIGINT, self._term_active_tasks)
        try:
            self._main_task = asyncio.ensure_future(task())
            self.loop.run_until_complete(self._main_task)
        except KeyboardInterrupt:
            pass
        except Exception as e:
            logger.exception(e)

    async def _run_shell(self):
        apps = self.runner.tree.get_applications()

        width, _ = os.get_terminal_size()
        banner = textwrap.dedent(f"""
            {"=" * (width)}
            W3plex interactive shell
            The following variables are available:
                - `apps`: all applications found in the config file.
                {{ {", ".join(set(apps.keys()))} }}
                - `cfg`: config loaded from the file {self.args.config}
                - `services`: dictionary of loaded from config services
                - `chains`: dictionary of loaded from config chains
                - `root`: resolved objects tree loaded from the config
            {"=" * width}
        """).strip()
        print(banner)

        globals = {
            'cfg': dict(self.cfg),
            'apps': apps,
            'services': AttrDict(self.runner.tree.get_services()),
            'chains': AttrDict(self.runner.tree.get_chains()),
            'root': self.runner.tree,
        }

        async def eval_async(repl, text):
            async def inner():
                result = await repl.__class__.eval_async(repl, text)
                if asyncio.iscoroutine(result):
                    result = await result
                return result
            task = asyncio.ensure_future(inner())

            self._active_tasks.add(task)
            try:
                return await task
            except asyncio.CancelledError:
                print(Text(f"`{text}` cancelled", "red"))
            finally:
                self._active_tasks.remove(task)

        def configure(repl):
            # make the repl process Futures without explicit await
            repl.eval_async = MethodType(eval_async, repl)

        await embed(globals=globals, return_asyncio_coroutine=True, configure=configure)


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
                or isfunction(value)
                or isinstance(value, Loader)):
            value = value()
        if iscoroutine(value):
            value = await value
        return value

    async def resolve_args(self, *args, **kwargs) -> Tuple[Tuple, Dict]:
        return (
            [await self.resolve_value(arg) for arg in args],
            {key: (await self.resolve_value(value)) for key, value in kwargs.items()}
        )

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
            args, kwargs = await self.resolve_args(*args, **kwargs)
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
        config_loader.add_node(
            r"^applications\.[^.]+$", 'applications'
        )(self.init_application)

        self._tree = await config_loader.parse(cfg, cfg_path)
        self.cfg = cfg
        self.cfg_path = cfg_path
        self.init_logger(cfg.get('logging') or [])

    def _parse_log_handler(self, config) -> Any:
        if (handler := config.pop('handler', None)) is not None:
            if isinstance(handler, str):
                return load_path(handler)
            return handler
        elif (filename := config.pop('file', None)) is not None:
            return os.path.join(os.path.dirname(self.cfg_path), filename)
        return sys.stderr

    def init_logger(self, loggers: List[Dict]):
        for log in loggers:
            kwargs = {
                "sink": self._parse_log_handler(log),
                "format": LOGGING_DEFAULT_FORMAT,
                "level": LOGGING_DEFAULT_LEVEL,
            }
            kwargs.update(log)
            logger.add(**kwargs)

    async def finalize(self):
        assert self.cfg is not None, "Not initialized, to be finilized"

        self.cfg = None
        self.cfg_path = None
        await asyncio.gather(*[
            service.finalize() for service in self._tree.get_services().values()
        ])

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
            CONTEXT_CHAINS_KEY: dict(chains if (chains := self.tree.get_chains()) else {}),
            CONTEXT_SERVICES_KEY: dict(services if (services := self.tree.get_services()) else {}),
        }):
            self._extend_app_actions(app, app_tree)
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


def run_shell_cmd(args, *, cfg, cfg_path):
    Shell(args, cfg, cfg_path)()


def run_app_cmd(args, *, name, cfg, cfg_path):
    app_args, app_kwargs = [], {}
    for item in getattr(args, 'args', []):
        parts = item.split("=", 1)
        if len(parts) == 1:
            if (len(app_kwargs)):
                raise AttributeError("A key=value argument cannot be followed by a positional argument.")
            app_args.append(parts[0])
        else:
            app_kwargs[parts[0]] = parts[1]

    runner = Runner()

    coro = None
    async def command():
        await runner.init(cfg, cfg_path)
        app = runner.tree.get(APPLICATIONS_CFG_KEY).get(name)
        if app is None:
            raise AttributeError(f"Application {name} not found")

        nonlocal coro
        coro = asyncio.ensure_future(
            runner.run_application(app, *app_args, **app_kwargs)
        )
        try:
            await coro
        finally:
            await runner.finalize()

    def cancel_coro():
        coro.cancel()

    runner.loop.add_signal_handler(signal.SIGINT, cancel_coro)

    try:
        runner.loop.run_until_complete(command())
    except asyncio.CancelledError:
        print(Text("Execution cancelled", "red"))
    # hack to clean up loop resources, once execution completed
    runner.loop.run_until_complete(asyncio.sleep(0))


def init_cmd(args):
    cfg = load_config(DEFAULT_CONFIG_PATH)

    chains = cfg.get('chains')
    # TODO: somehow comment in yaml doesn't work
    cfg['chains'] = Include(CHAINS_CONFIG_NAME, {'items': 'items: ["ethereum"]'})

    chains_path = os.path.join(os.path.dirname(args.config), CHAINS_CONFIG_NAME)
    if not os.path.exists(chains_path):
        with open(chains_path, 'w') as fw:
            yaml_dump(chains, fw, Dumper)
    with open(args.config, 'w') as fw:
        yaml_dump(cfg, fw, Dumper)


def load_config(filename: str) -> Dict[str, Any]:
    with open(filename) as fr:
        raw = fr.read()

    expanded = os.path.expandvars(raw)
    stream = io.StringIO(expanded)
    stream.name = os.path.abspath(filename)
    return yaml_load(stream, YamlLoader)


def load_applications(name: str):
    loaded = load_path(name)
    if isinstance(loaded, _Application):
        return [loaded]
    return [attr for attr in vars(loaded).values()
            if isinstance(attr, _Application)]


def main():
    # for w3plex development purposes add the package path
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    sys.path.insert(0, os.getcwd())

    process_args()


if __name__ == '__main__':
    main()
