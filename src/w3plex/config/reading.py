"""Config parsing without CLI imports, process environment changes or factories."""

import io
import os
import re
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, TextIO, cast

from ruamel import yaml

from w3plex.config.yaml import Dumper, Loader

from ..security import SecretRef
from ..security.errors import InvalidStore, PermissionDenied
from ..security.refs import _safe
from ..utils.dist import AttrDict

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


def load_reference_config(
    source: SecretRef[bytes],
    *,
    environment: Mapping[str, str],
    filename: str | Path = "w3plex.yaml",
    includes: Mapping[str | Path, SecretRef[bytes]] | None = None,
) -> AttrDict:
    """Read optional captured YAML through the existing configuration loader.

    Includes must be preloaded explicitly; this function never reads a source
    path from disk. Constructor names, paths and object references stay ordinary
    strings. External-file readers obtain references separately. Parsed config
    is private service data; Python parser objects cannot be reliably erased.
    """

    def operation():
        root = os.path.abspath(filename)
        sources = {
            os.path.abspath(path): value for path, value in (includes or {}).items()
        }
        sources[root] = source

        def opener(path, *args, **kwargs):
            selected = sources.get(os.path.abspath(path))
            if selected is None:
                raise PermissionDenied()
            return io.StringIO(selected._use(lambda raw: raw.decode("utf-8-sig")))

        values = load_config(root, opener=opener, environment=environment)

        def bind(value):
            if isinstance(value, dict):
                if any(type(key) is not str for key in value):
                    raise InvalidStore()
                result = AttrDict({key: bind(item) for key, item in value.items()})
                if included := getattr(value, "__include_path__", None):
                    setattr(result, "__include_path__", included)
                return result
            if isinstance(value, list):
                return [bind(item) for item in value]
            return value

        return cast(AttrDict, bind(values))

    return _safe(operation)
