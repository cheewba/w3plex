import argparse
import asyncio
import getpass
import glob
import io
import os
import sys
from functools import partial
from pathlib import Path
from typing import Any, TextIO, cast

from dotenv import load_dotenv
from rich import print
from ruamel.yaml import dump as yaml_dump
from ruamel.yaml import load as yaml_load

from w3plex.config import Dumper, Include
from w3plex.config import Loader as YamlLoader
from w3plex.constants import APPLICATIONS_CFG_KEY
from w3plex.runner import Runner
from w3plex.shell import Shell

load_dotenv(Path.cwd() / ".env")

CHAINS_CONFIG_NAME = "chains.yaml"
DEFAULT_CONFIG_PATH = str(Path(__file__).with_name("w3plex.yaml"))
EMPTY_PASSWORD = "<!empty>"


def subdict(d, ks):
    return {key: d[key] for key in ks}


def _get_base_args_parse(*args, **kwargs) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(*args, **kwargs)
    parser.add_argument(
        "--config", "-c", default="w3plex.yaml", help="YAML config path"
    )
    return parser


def process_args(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    cfg_args, remaining = _get_base_args_parse(add_help=False).parse_known_args(argv)
    cfg_path = os.path.abspath(cfg_args.config)
    cfg = None
    if (
        remaining
        and remaining[0] not in {"init", "encrypt", "decrypt"}
        and os.path.exists(cfg_path)
    ):
        cfg = load_config(cfg_path)

    parser = _get_base_args_parse()
    parser.set_defaults(config=cfg_args.config)
    actions = parser.add_subparsers(title="w3plex actions")

    def command(name, **kwargs):
        cmd = actions.add_parser(name, **kwargs)
        cmd.add_argument(
            "--config", "-c", default=argparse.SUPPRESS, help="YAML config path"
        )
        return cmd

    command("init", help="Create a starter config and wallet file").set_defaults(
        func=init_cmd
    )
    command("shell", help="Open the interactive Python shell").set_defaults(
        func=partial(run_shell_cmd, cfg=cfg, cfg_path=cfg_path)
    )
    for name in ("encrypt", "decrypt"):
        cmd = command(name, help=f"{name.capitalize()} files")
        cmd.add_argument("src", nargs="+", help="File paths or glob patterns")
        cmd.add_argument(
            "--password",
            "-p",
            nargs="?",
            const=EMPTY_PASSWORD,
            help="File password; omit the value to prompt",
        )
        destination = cmd.add_mutually_exclusive_group()
        destination.add_argument(
            "--output", "-o", dest="dst", help="Output path (one source only)"
        )
        destination.add_argument(
            "--overwrite",
            "-w",
            dest="inplace",
            action="store_true",
            help="Replace the source file",
        )
        if name == "encrypt":
            cmd.add_argument(
                "--add",
                "-a",
                dest="add_to_keystore",
                action="store_true",
                help="Remember the key in the encrypted keystore",
            )
        else:
            cmd.add_argument(
                "--keystore",
                "-k",
                dest="use_keystore",
                action="store_true",
                help="Try keys from the keystore",
            )
        cmd.set_defaults(func=partial(crypt_cmd, encrypt=name == "encrypt"))

    for app_name in (cfg or {}).get(APPLICATIONS_CFG_KEY, {}):
        cmd = command(app_name, help=f"Run the {app_name} application")
        cmd.add_argument("args", nargs="*", help="Action name and key=value arguments")
        cmd.set_defaults(
            func=partial(run_app_cmd, name=app_name, cfg=cfg, cfg_path=cfg_path)
        )

    args = parser.parse_args(argv)
    if func := getattr(args, "func", None):
        return func(args)
    parser.print_help()
    return None


def crypt_cmd(args, *, encrypt):
    from w3plex.secure import decrypt_file, encrypt_file

    files = sorted(
        {
            Path(filename)
            for pattern in args.src
            for filename in glob.glob(pattern, recursive=True)
            if Path(filename).is_file()
        }
    )
    if not files:
        raise FileNotFoundError("No source files matched")
    if args.dst and len(files) != 1:
        raise ValueError("--output requires exactly one source file")
    password = (
        getpass.getpass("File password: ")
        if args.password == EMPTY_PASSWORD
        else args.password
    )
    kwargs = {"password": password, "dst": args.dst, "inplace": args.inplace}
    fn = encrypt_file if encrypt else decrypt_file
    kwargs["add_to_keystore" if encrypt else "use_keystore"] = getattr(
        args, "add_to_keystore" if encrypt else "use_keystore"
    )
    for path in files:
        output = fn(path, **kwargs)
        print(f"{path} -> {output}")


def run_shell_cmd(args, *, cfg, cfg_path):
    if cfg is None:
        raise FileNotFoundError(
            f"Config not found: {cfg_path}. Run 'w3plex init' first."
        )
    Shell(cfg, cfg_path)()


def run_app_cmd(args, *, name, cfg, cfg_path):
    app_args, app_kwargs = [], {}
    for item in getattr(args, "args", []):
        key, separator, value = item.partition("=")
        if not separator:
            if app_kwargs:
                raise ValueError(
                    "Positional arguments must come before key=value arguments"
                )
            app_args.append(key)
        else:
            stream = io.StringIO(value)
            stream.name = cfg_path
            app_kwargs[key] = yaml_load(stream, YamlLoader) if value else ""

    async def command():
        runner = Runner()
        try:
            await runner.init(cfg, cfg_path)
            app = runner.tree.get(APPLICATIONS_CFG_KEY, {}).get(name)
            if app is None:
                raise ValueError(f"Application {name} not found")
            return await app(*app_args, **app_kwargs)
        finally:
            await runner.finalize()

    return asyncio.run(command())


def init_cmd(args):
    target = Path(args.config).absolute()
    if target.exists():
        raise FileExistsError(f"Config already exists: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    cfg = load_config(DEFAULT_CONFIG_PATH)
    cfg["chains"] = Include(CHAINS_CONFIG_NAME, items=["ethereum"])
    cfg["applications"]["balance"]["wallets"]["file"] = "wallets.txt"
    chains_path = target.with_name(CHAINS_CONFIG_NAME)
    if not chains_path.exists():
        chains_path.write_text(
            Path(__file__).with_name("config").joinpath("chains.yaml").read_text(),
            encoding="utf-8",
        )
    with open(target, "w") as stream:
        yaml_dump(cfg, stream, Dumper)
    wallets = target.with_name("wallets.txt")
    if not wallets.exists():
        wallets.write_text(
            "# One public EVM wallet address per line.\n", encoding="utf-8"
        )
    print(
        f"Created {target}. Set your RPC URL in {chains_path} and add addresses to {wallets}."
    )


def load_config(filename: str) -> dict[str, Any]:
    from w3plex.secure import _secure_open

    with cast(TextIO, _secure_open(filename, encoding="utf-8")) as stream:
        expanded = os.path.expandvars(stream.read())
    named = io.StringIO(expanded)
    named.name = os.path.abspath(filename)
    cfg = yaml_load(named, YamlLoader)
    if not isinstance(cfg, dict):
        raise TypeError(f"Config must be a YAML mapping: {filename}")
    return cfg


def main():
    sys.path.insert(0, os.getcwd())
    try:
        process_args()
    except KeyboardInterrupt:
        print("Execution cancelled", file=sys.stderr)
        sys.exit(130)
    except Exception as err:  # noqa: BLE001 -- CLI reports application failures
        print(str(err), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
