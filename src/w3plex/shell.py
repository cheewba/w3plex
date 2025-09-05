#!/usr/bin/env python
import asyncio
import os
import signal
import textwrap
from types import MethodType
from typing import Any

from ptpython.repl import embed
from rich import print
from rich.text import Text

from .utils import AttrDict
from .log import logger
from .runner import Runner


class Shell:
    def __init__(self, cfg, cfg_path) -> None:
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
        apps = self.runner.tree.get_collection("applications")

        width, _ = os.get_terminal_size()
        banner = textwrap.dedent(f"""
            {"=" * (width)}
            W3plex interactive shell
            The following variables are available:
                - `apps`: all applications found in the config file.
                {{ {", ".join(set(apps.keys()))} }}
                - `cfg`: config loaded from the file {self.cfg_path}
                - `chains`: dictionary of loaded from config chains
                - `root`: resolved objects tree loaded from the config
            {"=" * width}
        """).strip()
        print(banner)

        globals = {
            'cfg': dict(self.cfg),
            'apps': apps,
            'chains': AttrDict(self.runner.tree.get_collection('chains')),
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