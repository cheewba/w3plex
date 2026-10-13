"""Config parsing without CLI imports, process environment changes or factories."""

import io
import os
import re
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, TextIO, cast

from ruamel import yaml

from w3plex.config.yaml import Dumper, Loader

from ..security import SecretJson, SecretRef
from ..security.errors import InvalidStore, PermissionDenied
from ..security.refs import _safe
from ..security.vault_format import canonical
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
    """Read trusted YAML snapshots and replace string values with local references.

    Includes must be preloaded explicitly; this function never reads a source
    path from disk. Parsed/expanded values are encrypted as one new snapshot.
    Temporary Python parser objects cannot be reliably erased. The resulting
    config is private service data, not a model serialization format.
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

        def validate(value):
            if isinstance(value, dict):
                if any(type(key) is not str for key in value):
                    raise InvalidStore()
                for item in value.values():
                    validate(item)
            elif isinstance(value, list):
                for item in value:
                    validate(item)

        validate(values)
        captured = source._store.capture(canonical(values))

        def bind(value, path):
            if isinstance(value, str):
                return SecretJson[str](captured, path)
            if isinstance(value, dict):
                return AttrDict(
                    {key: bind(item, (*path, key)) for key, item in value.items()}
                )
            if isinstance(value, list):
                return [bind(item, (*path, index)) for index, item in enumerate(value)]
            return value

        return cast(AttrDict, bind(values, ()))

    return _safe(operation)
