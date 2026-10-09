from __future__ import annotations

import asyncio
import os
import re
from collections import defaultdict
from collections.abc import Awaitable, Callable
from inspect import isclass
from typing import (
    Any,
    cast,
    overload,
)

from lazyplex import Application, ContextScope
from w3ext import Chain

from ..constants import (
    ACTIONS_CFG_KEY,
    APPLICATIONS_CFG_KEY,
    CONTEXT_VARS_KEY,
    VARS_COLLECTION,
)
from ..exceptions import ConfigError
from ..utils import AttrDict, as_future, get_context, get_scope, load_path

__all__ = ["ConfigTree", "Lazy", "config_loader"]

type NodeConfig = dict[str, Any]
type NodeFactoryOutput[R] = (
    R | Awaitable[R]
    # TODO: add generators support
    # | Generator[R, object, object]
    # | AsyncGenerator[R, object]
)
type NodeFactory[R] = Callable[[Any, str], NodeFactoryOutput[R]]
type InitFactory[R] = Callable[..., NodeFactoryOutput[R]] | type[R]

COLLECTIONS = (("chains", Chain),)

IMPORT_KEY = "__init__"
VAR_KEY = "__var__"
AS_LAZY_KEY = "__lazy__"
AS_FACTORY_KEY = "__factory__"
ENTITY_RE = re.compile(r"\$([^.].*)$")
LAZY_ITEM_RE = re.compile(r"\$\.(.+)$")

APPLICATIONS_CFG_RE = re.compile(
    (_app_re := r"^.*" + APPLICATIONS_CFG_KEY + r"\.[^.]*") + r"$"
)
ACTION_CONFIG_RE = re.compile(_app_re + r"\." + ACTIONS_CFG_KEY + r"\.([^.]+)$")

empty = object()


def validate_relative_path(path, root=None):
    if not root or not isinstance(path, str):
        return path

    if not os.path.isabs(path):
        joined_path = os.path.join(root, path)
        if os.path.exists(joined_path):
            return joined_path
    return path


def validate_relative_import(path, root=None):
    if not root or not isinstance(path, str) or not path.startswith("."):
        return path

    level_up = len(path) - len(path.lstrip(".")) - 1
    base_components = root.split("/")
    if level_up <= len(base_components):
        base_components = base_components[: len(base_components) - level_up]
    else:
        raise ValueError(
            f"Too many leading dots in '{path}' for the given base path '{root}'"
        )

    relative_import = path[level_up + 1 :]
    full_import = ".".join(base_components + relative_import.split("."))
    return full_import.rstrip(".")


class SkipNode(Exception):
    pass


class _Resolver:
    def __init__(self) -> None:
        self._idx = {}
        self._later = defaultdict(list)

    def register(self, key, value):
        self._idx[key] = value
        for callback in self._later.pop(key, []):
            callback(value)

    def resolve_once_ready(self, value, callback):
        if value in self._idx:
            callback(self._idx[value])
            return True

        self._later[value].append(callback)
        return False

    def get_unresolved(self) -> list[str]:
        return list(self._later.keys())


class _ConfigLoader:
    def __init__(self) -> None:
        self._filters: list[
            tuple[
                Callable[[Any, str], bool],
                NodeFactory[Any],
                str | Callable[[Any], str] | None,
            ]
        ] = []

    def add_node[F: Callable[..., Any]](
        self,
        flt: Callable[[Any, str], bool] | str,
        collection: str | Callable[[Any], str] | None = None,
    ) -> Callable[[F], F]:
        predicate = self._regexp_flt(flt) if isinstance(flt, str) else flt

        def inner(fn: F) -> F:
            self._filters.append((predicate, fn, collection))
            return fn

        return inner

    def _regexp_flt(self, regexp: str):
        _regexp = re.compile(regexp)

        def _filter(cfg: dict, path: str) -> bool:
            return _regexp.match(path) is not None

        return _filter

    async def get_node(
        self,
        cfg: Any,
        path: str,
        collections: defaultdict | None = None,
        relative_path: str | None = None,
    ) -> Any:

        node = cfg
        is_var = isinstance(cfg, dict) and cfg.pop(VAR_KEY, False)
        for flt, node_fn, collection in self._filters[::-1]:
            # check filters as LIFO
            if flt(cfg, path):
                try:
                    node = await as_future(node_fn(cfg, path))
                    if node and collection and collections is not None:
                        if isinstance(collection, Callable):
                            collection = collection(node)
                        collections[collection][path.rsplit(".", 1)[-1]] = node
                    break
                except SkipNode:
                    continue

        if is_var:
            if collections is None:
                raise ConfigError("Variables require a config collection")
            collections[VARS_COLLECTION][path.split(".")[-1]] = node

        return node

    async def parse(self, cfg: dict, cfg_path: str) -> ConfigTree:
        unresolved_states = []

        def get_node_rel_path(node, root_path: str) -> str | None:
            child = getattr(node, "__include_path__", None)
            return os.path.relpath(os.path.dirname(child), root_path) if child else None

        def _resolve(collection, value, key, state):
            def callback(val):
                collection[key] = val
                state["unresolved"] -= 1

            if isinstance(value, str) and (entity_match := ENTITY_RE.match(value)):
                state["unresolved"] += 1
                resolver.resolve_once_ready(entity_match.group(1), callback)

        async def _parse_item(key, value, state, path, relative_path):
            if isinstance(value, dict):
                value_path = ".".join([path, str(key)]) if path else str(key)
                entity = await _parse_cfg(
                    value,
                    value_path,
                    collections,
                    get_node_rel_path(value, relative_path) or relative_path,
                )
                if entity:
                    if not isinstance(entity, dict):
                        resolver.register(value_path, entity)
                    value = entity
            elif isinstance(value, list):
                parsed = []
                for i, item in enumerate(value):
                    parsed.append(
                        await _parse_item(i, item, state, path, relative_path)
                    )
                    _resolve(value, item, i, state)
                value = parsed
            elif isinstance(value, str):
                _resolve(state["parsed"], value, key, state)

            return value

        async def _parse_cfg(
            cfg: dict,
            path: str = "",
            collections: defaultdict | None = None,
            relative_path: str | None = None,
        ) -> Any:
            if collections is None:
                collections = defaultdict(list)
            state = {"parsed": (parsed := AttrDict()), "unresolved": 0, "path": path}
            for key, value in cfg.items():
                value = await _parse_item(key, value, state, path, relative_path)
                if key not in parsed:
                    value = validate_relative_path(value, relative_path)
                    value = validate_relative_import(value, relative_path)
                    parsed[key] = value

                if not path:
                    # on 0 level we can try to resolve node once it's parsed
                    parsed[key] = await self.get_node(
                        parsed[key], key, collections, relative_path
                    )

            if not path:
                return parsed

            if path and state["unresolved"] == 0:
                # on 1+ level parse node only after all items on that level parsed
                return await self.get_node(parsed, path, collections, relative_path)

            unresolved_states.append(state)
            return None

        resolver = _Resolver()
        parsed = await _parse_cfg(
            cfg,
            "",
            collections := defaultdict(AttrDict),
            get_node_rel_path(cfg, os.path.dirname(cfg_path)),
        )
        assert isinstance(parsed, AttrDict)

        unresolved = resolver.get_unresolved()
        while True:
            i = 0
            while i < len(unresolved_states):
                state = unresolved_states[i]
                if state["unresolved"] == 0:
                    path = state["path"].split(".")
                    parent = parsed
                    for item in path[:-1]:
                        parent = parent[item]
                    parent[path[-1]] = await self.get_node(
                        state["parsed"], state["path"], collections
                    )
                    unresolved_states.pop(i)
                    continue
                i += 1
            if unresolved == resolver.get_unresolved():
                break

        if unresolved := resolver.get_unresolved():
            raise ConfigError(f"Can't resolve config items: {', '.join(unresolved)}")

        return ConfigTree(parsed, collections)


class ConfigTree(AttrDict):
    def __init__(self, tree, collections: dict[str, AttrDict] | None = None):
        super().__init__(tree)
        self._collections = collections if collections is not None else {}

    def get_collection(self, name: str):
        return self._collections.get(name)

    def get_collections(self):
        return dict(self._collections)

    async def close(self):
        pass


config_loader = _ConfigLoader()


def _entity_filter(cfg: Any, path: str) -> bool:
    return isinstance(cfg, dict) and IMPORT_KEY in cfg


def _get_entity_collection(entity: Any) -> str:
    for collection, cls in COLLECTIONS:
        if isinstance(entity, cls):
            return collection
    return ""


@config_loader.add_node(_entity_filter, _get_entity_collection)
async def entity_factory(cfg: NodeConfig, path: str) -> NodeFactoryOutput:
    conf = dict(cfg)  # create a copy to modify it
    init_path = conf.pop(IMPORT_KEY)
    init = load_path(init_path)

    if isinstance(init, Application):
        # for application there's another protocol
        raise SkipNode

    if isclass(init) and issubclass(init, Chain):
        return await load_chain(conf, path, init)
    if (
        len([val for val in cfg.values() if isinstance(val, Lazy) and not val.as_lazy])
        > 0
    ):
        entity = await lazy_factory(cfg, path)
    else:
        if not callable(init):
            raise ConfigError(f"Config initializer '{init_path}' is not callable")
        entity = await as_future(init(**conf))

    return entity


@overload
async def load_chain(cfg: NodeConfig, path: str) -> Chain: ...
@overload
async def load_chain[R: Chain](cfg: NodeConfig, path: str, cls: type[R]) -> R: ...


@config_loader.add_node(
    r"^chains\.[^.]+$", "chains"
)  # default location for chains in config file
async def load_chain(
    cfg: NodeConfig, path: str, cls: type[Chain] | None = None
) -> Chain:
    cls = cls or Chain
    erc20 = cfg.pop("erc20", None)
    chain = await cls.connect(name=path.rsplit(".", 1)[-1], **cfg)
    if erc20:
        await asyncio.gather(
            *[chain.load_token(token, cache_as=key) for key, token in erc20.items()]
        )
    return chain


def _lazy_filter(cfg: Any, path: str) -> bool:
    if not isinstance(cfg, dict):
        return False
    return (
        cfg.get(AS_LAZY_KEY, False)
        or cfg.get(AS_FACTORY_KEY, False)
        or (
            len(
                [
                    val
                    for val in cfg.values()
                    if isinstance(val, str) and LAZY_ITEM_RE.match(val)
                ]
            )
            > 0
        )
    )


@config_loader.add_node(_lazy_filter)
async def lazy_factory(cfg: NodeConfig, path: str) -> dict[str, Any] | Lazy[Any]:
    if APPLICATIONS_CFG_RE.match(path) or ACTION_CONFIG_RE.match(path):
        # Application and Action can't be Lazy instance
        # but seems they have a field expected to be a Lazy
        output = dict(cfg)
        for key, val in cfg.items():
            if isinstance(val, str) and LAZY_ITEM_RE.match(val):
                output[key] = LazyVar(val, f"{path}.{key}")
        return output

    return Lazy(cfg, path)


class Lazy[T]:
    _as_factory = False
    _as_lazy = False

    def __init__(self, cfg: NodeConfig, path: str):
        self._as_lazy = cfg.pop(AS_LAZY_KEY, False)
        self._as_factory = cfg.pop(AS_FACTORY_KEY, False)

        self.cfg = cfg
        self.path = path

    @property
    def as_lazy(self):
        return self._as_lazy or self._as_factory

    @property
    def as_factory(self):
        return self._as_factory

    @property
    def type(self) -> type[T] | None:
        return None

    def _resolve_path(self, path: str, vars: dict[str, Any]) -> Any:
        """
        Resolves a dot-separated path against the provided vars.
        Each segment can resolve as:
        - Mapping key (dict-like)
        - Object attribute (getattr)
        - Iterable/sequence index (when the segment is an integer)
        """
        if not isinstance(path, str):
            raise TypeError("path must be a string")

        def get_attr(item, key):
            try:
                return getattr(item, key)
            except AttributeError:
                return empty

        def get_item(item, key):
            try:
                return item[key]
            except KeyError:
                return empty

        def get_index(item, idx):
            try:
                return item[int(idx)]
            except (ValueError, IndexError):
                return empty

        current = vars
        for segment in path.split("."):
            if segment == "":
                continue

            for resolver in (get_item, get_attr, get_index):
                resolved = resolver(current, segment)
                if resolved is not empty:
                    current = resolved
                    break
                raise ConfigError(f"Can't resolve {path} to value")
        return current

    def _set_cached(self, value: T):
        if get_scope() == ContextScope.action:
            ctx = get_context()
            if ctx is None:
                raise ConfigError("Lazy action cache requires an application context")
            ctx.setdefault("_lazy_cache", {})[self.path] = value
        else:
            # when scope is an application, behave like a singleton
            self._cached = value

    def _get_cached(self) -> T | object:
        if get_scope() == ContextScope.action:
            ctx = get_context() or {}
            cache = ctx.get("_lazy_cache") or {}
            return cache.get(self.path, empty)
        else:
            return getattr(self, "_cached", empty)

    async def __call__(self, **kwargs) -> T:
        if not self.as_factory and (value := self._get_cached()) is not empty:
            return cast(T, value)

        kw = dict(self.cfg)
        kw.update(kwargs)

        ctx = get_context() or {}

        vars = {
            "vars": ctx.get(CONTEXT_VARS_KEY) or {},
            "context": ctx,
        }
        for key, value in kw.items():
            if isinstance(value, str) and (match := LAZY_ITEM_RE.match(value)):
                kw[key] = value = self._resolve_path(match.group(1), vars)
            if isinstance(value, Lazy) and not value.as_lazy:
                kw[key] = await value()
        value = cast(T, await config_loader.get_node(kw, self.path))
        if not self.as_factory:
            self._set_cached(value)
        return value


class LazyVar[T](Lazy[T]):
    def __init__(self, var: str, path: str):
        self._as_lazy = False

        self.var = var
        self.path = path

    async def __call__(self, **kwargs) -> T:
        if (value := self._get_cached()) is not empty:
            return cast(T, value)

        ctx = get_context() or {}

        vars = {
            "vars": ctx.get(CONTEXT_VARS_KEY) or {},
            "context": ctx,
        }
        match = LAZY_ITEM_RE.match(self.var)
        if match is None:
            raise ConfigError(f"Invalid lazy variable: {self.var}")
        value = self._resolve_path(match.group(1), vars)
        if isinstance(value, Lazy) and not value.as_lazy:
            value = await value()
        resolved = cast(T, value)
        self._set_cached(resolved)
        return resolved
