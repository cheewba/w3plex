"""Read config data without importing the CLI or creating configured objects."""

import io
import os
import re
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, TextIO, cast

from ruamel import yaml

from w3plex.config.yaml import Dumper, Loader

from ..security import ISecretRef
from ..security.diagnostics import private_call
from ..security.errors import InvalidStore, PermissionDenied
from ..utils.dist import AttrDict

Opener = Callable[..., TextIO]
_VARIABLE = re.compile(r"\$(?:\{(?P<braced>[^}]+)\}|(?P<plain>\w+))")


def _expand(text: str, environment: Mapping[str, str]) -> str:
    def replace(match: re.Match[str]) -> str:
        return environment.get(match.group("braced") or match.group("plain"), match[0])

    return _VARIABLE.sub(replace, text)


def load_config(
    filename: str | Path,
    *,
    opener: Opener,
    environment: Mapping[str, str],
    include_encoding: str | None = "utf-8",
) -> dict[str, Any]:
    """Read trusted YAML without running configuration factories.

    Includes use the same opener and environment. Validate untrusted settings before
    using them as application configuration.

    Args:
        filename: Path of the root YAML file.
        opener: Open-compatible function used for the root file and its includes.
        environment: Variable names and text values used for expansion. Unknown names
            stay unchanged.
        include_encoding: Encoding for included files. None uses the system default.

    Returns:
        The config as a dictionary.
    """
    path = os.path.abspath(filename)
    env = dict(environment)

    class ExplicitLoader(Loader):
        def _load_yaml(self, filename):
            return read(filename, encoding=include_encoding)

    # Loader.include calls self._load_yaml; recursive includes keep this loader.
    def read(target, *, encoding: str | None = "utf-8"):
        with opener(target, "r", encoding=encoding) as stream:
            named = io.StringIO(_expand(stream.read(), env))
        named.name = os.path.abspath(target)
        return yaml.load(named, Loader=ExplicitLoader)

    result = read(path)
    if not isinstance(result, dict):
        raise TypeError(f"Config must be a YAML mapping: {filename}")
    return result


def create_config(
    filename: str | Path, values: Mapping[str, Any], *, opener: Opener
) -> Path:
    """Create a config file without replacing an existing file.

    Args:
        filename: Path of the new file. Its parent directory must already exist.
        values: Public config values to write as YAML.
        opener: Open-compatible function used to create the file in exclusive mode.

    Returns:
        The path of the created file.
    """
    path = Path(filename)
    rendered = yaml.dump(dict(values), Dumper=Dumper)
    with opener(path, "x", encoding="utf-8") as stream:
        stream.write(rendered)
    return path


def load_reference_config(
    source: ISecretRef[bytes],
    *,
    environment: Mapping[str, str],
    filename: str | Path = "w3plex.yaml",
    includes: Mapping[str | Path, ISecretRef[bytes]] | None = None,
) -> AttrDict:
    """Read YAML from captured bytes instead of opening source files.

    All includes must be provided in advance. The parsed config may contain private data
    and remains in normal Python memory.

    Args:
        source: Reference to the root YAML bytes.
        environment: Variable names and text values used for expansion.
        filename: Source name used to resolve include paths. This file is not opened.
        includes: Optional mapping from include paths to captured byte references.

    Returns:
        Config data with attribute access and the original include path information.
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
            return io.StringIO(selected.ref(silent=True).decode("utf-8-sig"))

        values = load_config(root, opener=opener, environment=environment)

        def bind(value):
            if isinstance(value, dict):
                if any(type(key) is not str for key in value):
                    raise InvalidStore()
                result = AttrDict({key: bind(item) for key, item in value.items()})
                if included := getattr(value, "__include_path__", None):
                    cast(Any, result).__include_path__ = included
                return result
            if isinstance(value, list):
                return [bind(item) for item in value]
            return value

        return cast(AttrDict, bind(values))

    return private_call(operation)
