#!/usr/bin/env python
import asyncio
import argparse
import logging
import os
import sys
import signal
import textwrap
import traceback
from collections import namedtuple
from contextlib import contextmanager
from functools import partial, wraps
from types import MethodType
from typing import Dict, Any, Tuple, Optional, Dict

from rich import print
from rich.text import Text
from ruamel.yaml import load as yaml_load, dump as yaml_dump
from lazyplex import Application as _Application, create_context
from w3ext import Chain
from ptpython.repl import embed

from .utils import load_path
from .constants import CONTEXT_CHAINS_KEY, CONTEXT_SERVICES_KEY
from .services import Service, ServiceConfig
from .utils import load_path, AttrDict
from .yaml import Dumper, Loader, Include


logger = logging.getLogger(__name__)

CHAINS_CONFIG_NAME = 'chains.yaml'
DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(__file__), 'w3plex.yaml')
APPLICATIONS_CFG_KEY = 'applications'
ACTIONS_CFG_KEY = 'actions'


def _get_base_args_parse(*args, **kwargs) -> Tuple[argparse.ArgumentParser]:
    parser = argparse.ArgumentParser(*args, **kwargs)
    parser.add_argument('--config', '-c', help='run using w3plex config file', default='w3plex.yaml')

    return parser


def process_args():
    cfg_parser = _get_base_args_parse(add_help=False)
    cfg_parser.add_argument('kwargs', nargs="*")
    cfg_args, _ = cfg_parser.parse_known_args()

    cfg = load_config(cfg_args.config) if os.path.exists(cfg_args.config) else None

    parser = _get_base_args_parse()
    actions = parser.add_subparsers(title="w3plex actions", required=False)
    init = actions.add_parser('init', description="Initialize a new config")
    init.set_defaults(func=init_cmd)

    if cfg is not None:
        shell = actions.add_parser('shell', description="Start w3ext shell for the current config")
        shell.set_defaults(func=partial(run_shell_cmd, cfg=cfg))

        for app_name in cfg.get(APPLICATIONS_CFG_KEY, {}).keys():
            cmd = actions.add_parser(app_name, description=f"Run `{app_name}` application")
            cmd.add_argument("args", nargs='*', default=[], help="Single value or Key-value pairs separated by a comma. (e.g., value1 key2=value2)")
            cmd.set_defaults(func=partial(run_app_cmd, name=app_name, cfg=cfg))

    args = parser.parse_args(" ".join(sys.argv[1:]).split(" "))

    func = getattr(args, 'func', None)
    if func is not None:
        return func(args)


class Shell:
    def __init__(self, args, cfg) -> None:
        self.args = args
        self.cfg = cfg
        self.loop = asyncio.get_event_loop()
        self.runner = Runner(self.loop)

        self._active_tasks: set[asyncio.Future] = set()
        self._main_task = None

    def _load_config_applications(self):
        result = {}
        def wrap_app(app):
            @wraps(app)
            def runner(*args, **kwargs):
                return self.runner.run_application(app, *args, **kwargs)
            return runner

        for app_name, app_cfg in self.cfg.get(APPLICATIONS_CFG_KEY, {}).items():
            if (app_module := app_cfg.get('application')) is None:
                raise AttributeError(f"{app_name}: field `application` is required")
            apps = load_applications(app_module)
            if not len(apps):
                raise ValueError(f"No applications found for path '{app_module}'")
            result[app_name] = wrap_app(apps[0])

        return namedtuple("app", result.keys())(*result.values())

    def _term_active_tasks(self):
        for task in self._active_tasks:
            task.cancel()

    def __call__(self) -> Any:
        async def task():
            await self.runner.init(self.cfg)
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
        except Exception:
            logger.exception()

    async def _run_shell(self):
        apps = self._load_config_applications()

        width, _ = os.get_terminal_size()
        banner = textwrap.dedent(f"""
            {"=" * (width)}
            W3plex interactive shell
            The following variables are available:
                - `app`: contains all available applications from the config file.
                {{ {", ".join(set(apps._fields))} }}
                - `cfg`: config loaded from the file {self.args.config}
                - `services`: dictionary of loaded from config services
                - `chains`: dictionary of loaded from config chains
            {"=" * width}
        """).strip()
        print(banner)

        globals = {
            'app': apps,
            'cfg': dict(self.cfg),
            'services': AttrDict(self.runner.services),
            'chains': AttrDict(self.runner.chains),
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
    chains: Optional[Dict[str, Chain]] = None
    services: Optional[Dict[str, Service]] = None

    def __init__(self, loop=None) -> None:
        self.loop: asyncio.AbstractEventLoop = loop or asyncio.get_event_loop()

    @property
    def is_initialized(self) -> bool:
        return self.cfg is not None

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
            await app(*args, **kwargs)

    async def init(self, cfg):
        assert self.cfg is None, "Already initialized. Finalize first."

        self.cfg = cfg
        self.services = await self._init_services()
        self.chains = await self._load_chains()

    async def finalize(self):
        assert self.cfg is not None, "Not initialized, to be finilized"

        self.cfg = None
        await asyncio.gather(*[
            service.finalize() for service in self.services.values()
        ])
        self.services = None
        self.chains = None

    async def _init_service(
        self,
        name: str,
        config: ServiceConfig,
    ) -> Dict[str, "Service"]:
        service: Service = load_path(config['service'])(config)
        await service.init()

        return name, service

    async def _init_services(self):
        services = self.cfg.get('services')
        return dict(await asyncio.gather(
            *(self._init_service(name, cfg)
              for name, cfg in services.items())
        ))

    async def _load_chain(
        self,
        name: str,
        *,
        erc20: Optional[dict] = None,
        **chain_info
    ) -> Dict[str, "Chain"]:
        chain = await Chain.connect(name=name, **chain_info)
        if (erc20):
            await asyncio.gather(*[chain.load_token(token, cache_as=key)
                                   for key, token in erc20.items()])
        return name, chain

    async def _load_chains(self):
        chains = self.cfg.get('chains') or {}
        return dict(await asyncio.gather(
            *(self._load_chain(name, **info) for name, info in chains.items())
        ))

    @contextmanager
    def _app_context(self, app: _Application):
        # place w3plex import here to let main() function
        # add appropriate package to the PATH
        from w3plex.constants import CONTEXT_CONFIG_KEY, CONTEXT_EXTRAS_KEY

        cfg = dict(self.cfg)
        app_cfg = cfg.pop(APPLICATIONS_CFG_KEY).get(app.name)
        with create_context({
            CONTEXT_CONFIG_KEY: dict(app_cfg),
            CONTEXT_EXTRAS_KEY: dict(cfg),
            CONTEXT_CHAINS_KEY: dict(self.chains),
            CONTEXT_SERVICES_KEY: dict(self.services),
        }):
            self._extend_app_actions(app, app_cfg)
            yield app

    def _extend_app_actions(self, app: _Application, app_cfg: Dict):
        for action_name, action_cfg in app_cfg.get(ACTIONS_CFG_KEY, {}).items():
            action_cfg = dict(action_cfg)  # create a copy to modify it
            action_base = action_cfg.pop('action', None) or action_name
            app_action = app._actions.get(action_base)
            if app_action is None:
                raise ValueError(f"Application '{app.name}' doesn't have any action, "
                                f"that could be bound to config action '{action_name}'")
            app._actions[action_name] = partial(app_action, config=action_cfg)


def run_shell_cmd(args, *, cfg):
    Shell(args, cfg)()


def run_app_cmd(args, *, name, cfg):
    app_cfg = cfg.get(APPLICATIONS_CFG_KEY).get(name)
    if (app_module := app_cfg.get('application')) is None:
        raise AttributeError(f"{name}: field `application` is required")

    apps = load_applications(app_module)
    if not apps:
        raise ValueError(f'{name}: can\'t load application "{app_module}"')

    (app := apps[0]).name = name
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
        await runner.init(cfg)

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
        return yaml_load(fr, Loader)


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
