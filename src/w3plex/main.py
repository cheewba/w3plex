#!/usr/bin/env python
import argparse
import asyncio
import getpass
import io
import itertools
import os
import signal
import sys
from functools import partial
from pathlib import Path
from operator import itemgetter
from typing import Any, Dict, Tuple

from dotenv import load_dotenv
from rich import print
from rich.text import Text
from ruamel.yaml import (
    dump as yaml_dump,
    load as yaml_load,
)

from w3plex.constants import APPLICATIONS_CFG_KEY
from w3plex.runner import Runner
from w3plex.shell import Shell
from w3plex.secure import encrypt_file, decrypt_file
from w3plex.yaml import Dumper, Include, Loader as YamlLoader


load_dotenv()

CHAINS_CONFIG_NAME = 'chains.yaml'
DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(__file__), 'w3plex.yaml')


def subdict(d, ks):
    return dict(zip(ks, itemgetter(*ks)(d)))


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

    empty_pass = "<!empty>"
    if cfg is not None:
        shell = actions.add_parser('shell', description="Start w3ext shell for the current config")
        shell.set_defaults(func=partial(run_shell_cmd, cfg=cfg, cfg_path=cfg_path))

        encrypt_cmd = actions.add_parser('encrypt', description="Encrypt provided file")
        encrypt_cmd.add_argument('src', nargs="+", help='Path to the file to encrypt')
        encrypt_cmd.add_argument('--password', '-p', nargs="?", const=empty_pass, dest='password',
                                 help='Password to encrypt the file with')
        encrypt_cmd.add_argument('--output', '-o', dest='dst', help='Output file path')
        encrypt_cmd.add_argument('--overwrite', '-w', dest='inplace', action='store_true',
                                 help='Overwrite the original file')
        encrypt_cmd.add_argument('--add', '-a', dest='add_to_keystore', action='store_true',
                                 help='Add provided encryption key to the keystore')
        def _encrypt_file(args):
            kwargs = subdict(vars(args), ["src", "dst", "password", "inplace",
                                          "add_to_keystore"])
            files = set(itertools.chain(
                *(list(Path().glob(src)) for src in kwargs.pop('src'))
            ))
            if kwargs.get('password') == empty_pass:
                kwargs['password'] = getpass.getpass("Enter password: ")
            if len(files) > 1:
                # in case more than one file, --output won't work
                kwargs.pop('dst', None)
            for path in files:
                try:
                    encrypt_file(path, **kwargs)
                    print(f"File {path} encrypted")
                except Exception as e:
                    print(f"Failed to encrypt file {path}: {e}",
                          file=sys.stderr)
        encrypt_cmd.set_defaults(func=_encrypt_file)

        decrypt_cmd = actions.add_parser('decrypt', description="Decrypt provided file")
        decrypt_cmd.add_argument('src', nargs="+", help='Path to the file to encrypt')
        decrypt_cmd.add_argument('--password', '-p', nargs="?", const=empty_pass, dest='password',
                                 help='Password to decrypt the file with')
        decrypt_cmd.add_argument('--output', '-o', dest='dst', help='Output file path')
        decrypt_cmd.add_argument('--overwrite', '-w', dest='inplace', action='store_true',
                                 help='Overwrite the original file')
        decrypt_cmd.add_argument('--keystore', '-k', dest='use_keystore', action='store_true',
                                 help='Use keystore for encryption')
        def _decrypt_file(args):
            kwargs = subdict(vars(args), ["src", "dst", "password", "inplace",
                                          "use_keystore"])
            files = set(itertools.chain(
                *(list(Path().glob(src)) for src in kwargs.pop('src'))
            ))
            if kwargs.get('password') == empty_pass:
                kwargs['password'] = getpass.getpass("Enter password: ")
            if len(files) > 1:
                # in case more than one file, --output won't work
                kwargs.pop('dst', None)
            for path in files:
                try:
                    decrypt_file(path, **kwargs)
                    print(f"File {path} decrypted")
                except Exception as e:
                    print(f"Failed to decrypt file {path}: {e}",
                          file=sys.stderr)
        decrypt_cmd.set_defaults(func=_decrypt_file)

        for app_name in cfg.get(APPLICATIONS_CFG_KEY, {}).keys():
            cmd = actions.add_parser(app_name, description=f"Run `{app_name}` application")
            cmd.add_argument("args", nargs='*', default=[], help="Single value or Key-value pairs separated by a comma. (e.g., value1 key2=value2)")
            cmd.set_defaults(func=partial(run_app_cmd, name=app_name, cfg=cfg,
                                          cfg_path=cfg_path))

    args = parser.parse_args(" ".join(sys.argv[1:]).split(" "))

    func = getattr(args, 'func', None)
    if func is not None:
        return func(args)


def run_shell_cmd(args, *, cfg, cfg_path):
    Shell(cfg, cfg_path)()


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


def main():
    # # for w3plex development purposes add the package path
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    sys.path.insert(0, os.getcwd())

    try:
        process_args()
    except Exception as err:
        sys.stderr(err)
        sys.stderr.flush()
        sys.exit(1)


if __name__ == '__main__':
    main()
