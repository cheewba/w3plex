"""Config parsing without CLI imports, process environment changes or factories."""

import io
import os
import re
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, TextIO

from ruamel import yaml

from w3plex.config.yaml import Dumper, Loader

Opener = Callable[..., TextIO]
_VARIABLE = re.compile(r"\$(?:\{(?P<braced>[^}]+)\}|(?P<plain>\w+))")


def _expand(text: str, environment: Mapping[str, str]) -> str:
    def replace(match: re.Match[str]) -> str:
        return environment.get(match.group("braced") or match.group("plain"), match[0])

    return _VARIABLE.sub(replace, text)


def load_config(
    filename: str | Path, *, opener: Opener, environment: Mapping[str, str]
) -> dict[str, Any]:
    """Read trusted legacy YAML as data. Includes use the same explicit inputs.

    This function does not instantiate YAML factories. Model-provided settings
    must be validated separately against an application schema before use.
    """
    path = os.path.abspath(filename)
    env = dict(environment)

    class ExplicitLoader(Loader):
        def _load_yaml(self, filename):
            return read(filename)

    # Loader.include calls self._load_yaml; recursive includes keep this loader.
    def read(target):
        with opener(target, "r", encoding="utf-8") as stream:
            named = io.StringIO(_expand(stream.read(), env))
        named.name = os.path.abspath(target)
        return yaml.load(named, Loader=ExplicitLoader)

    result = read(path)
    if not isinstance(result, dict):
        raise TypeError("Config must be a YAML mapping")
    return result


def create_config(
    filename: str | Path, values: Mapping[str, Any], *, opener: Opener
) -> Path:
    """Create a trusted public config exclusively; never replace an existing file.

    The caller supplies public values and owns parent-directory creation.
    Exclusive mode also rejects dangling symlinks and races with other creators.
    """
    path = Path(filename)
    rendered = yaml.dump(dict(values), Dumper=Dumper)
    with opener(path, "x", encoding="utf-8") as stream:
        stream.write(rendered)
    return path
