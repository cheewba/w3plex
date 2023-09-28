#!/usr/bin/env python
import argparse
import logging
import os
import sys
from functools import partial
from importlib import import_module
from typing import Dict, Any, Tuple

import ruamel.yaml as yaml
from lazyplex import Application


logger = logging.getLogger(__name__)

DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(__file__), 'w3plex.yaml')
APPLICATIONS_CFG_KEY = 'applications'


# Check if a string starts with '0x' and has valid hexadecimal digits afterwards
def is_hex(value):
    if not value.startswith("0x"):
        return False
    try:
        int(value, 16)
        return True
    except ValueError:
        return False


class Loader(yaml.RoundTripLoader):
    """ Custom loader that supports !include directive. """
    def __init__(self, stream, *args, **kwargs):
        self._root = os.path.split(stream.name)[0]
        super(Loader, self).__init__(stream, *args, **kwargs)

    def include(self, node):
        filename = os.path.join(self._root, self.construct_scalar(node))
        with open(filename, 'r') as f:
            return yaml.load(f, Loader)

    # Custom constructor for values that start with "0x"
    def hex_string_constructor(self, node):
        if isinstance(node, yaml.ScalarNode):
            value = self.construct_scalar(node)
            if is_hex(value):
                return str(value)
        return self.construct_yaml_int(node)

Loader.add_constructor(u'tag:yaml.org,2002:int', Loader.hex_string_constructor)
Loader.add_constructor('!include', Loader.include)


class Dumper(yaml.RoundTripDumper):
    def increase_indent(self, flow=False, sequence=False, *args, **kwargs):
        return super(Dumper, self).increase_indent(flow, False, *args, **kwargs)

    # Custom representer for "0x" strings
    def represent_hex_string(self, data):
        return self.represent_scalar(u'tag:yaml.org,2002:str', data)

Dumper.add_representer(str, Dumper.represent_hex_string)


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
        for app_name in cfg.get(APPLICATIONS_CFG_KEY, {}).keys():
            cmd = actions.add_parser(app_name, description=f"Run `{app_name}` application")
            cmd.set_defaults(func=partial(run_app_cmd, name=app_name, cfg=cfg))

    args = parser.parse_args()
    func = getattr(args, 'func', None)
    if func is not None:
        return func(args)


def run_app_cmd(args, *, name, cfg):
    # place w3plex import here to let main() function
    # add appropriate package to the PATH
    from w3plex.constants import CONTEXT_CONFIG_KEY, CONTEXT_EXTRAS_KEY

    app_cfg = cfg.pop(APPLICATIONS_CFG_KEY).get(name)
    if (app_module := app_cfg.get('application')) is None:
        raise AttributeError(f"{name}: field `application` is required")

    apps = load_applications(app_module)
    if not apps:
        raise ValueError(f'{name}: can\'t load application "{app_module}"')

    (app := apps[0]).name = name

    app.run_until_complete({
        CONTEXT_CONFIG_KEY: dict(app_cfg),
        CONTEXT_EXTRAS_KEY: dict(cfg),
    })


def init_cmd(args):
    cfg = load_config(DEFAULT_CONFIG_PATH)

    with open(args.config, 'w') as fw:
        yaml.dump(cfg, fw, yaml.RoundTripDumper)


def load_config(filename: str) -> Dict[str, Any]:
    with open(filename) as fr:
        return yaml.load(fr, Loader)


def load_applications(name: str):
    parts = name.split(":")
    loaded = import_module(parts[0])
    if len(parts) > 1:
        return [getattr(loaded, parts[1])]
    return [attr for attr in vars(loaded).values()
            if isinstance(attr, Application)]


def main():
    # for w3plex development purposes add the package path
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    sys.path.insert(0, os.getcwd())

    process_args()


if __name__ == '__main__':
    main()
