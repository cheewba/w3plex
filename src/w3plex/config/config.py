from __future__ import annotations

import asyncio
import os
import re
from collections import defaultdict
from collections.abc import Awaitable, Callable
from contextlib import AsyncExitStack, asynccontextmanager, contextmanager
from inspect import getattr_static, isasyncgen, isawaitable, isclass, isgenerator
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
type NodeFactoryOutput[R] = R | Awaitable[R]
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


def _get_close(node):
    # Some configured objects synthesize attributes (e.g. application argument
    # decorators). Only actual cleanup methods indicate resource ownership.
    return node.close if callable(getattr_static(node, "close", None)) else None


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

    def clone(self) -> _ConfigLoader:
        loader = _ConfigLoader()
        loader._filters = self._filters.copy()
        return loader

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
        prepare: Callable[[Any], Awaitable[Any]] | None = None,
    ) -> Any:

        node = cfg
        is_var = isinstance(cfg, dict) and cfg.pop(VAR_KEY, False)
        for flt, node_fn, collection in self._filters[::-1]:
            # check filters as LIFO
            if flt(cfg, path):
                try:
                    node = await as_future(node_fn(cfg, path))
                    if prepare is not None:
                        node = await prepare(node)
                    if node is not None and collection and collections is not None:
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
        """Resolve dependencies once, including forward references inside lists."""
        collections = defaultdict(AttrDict)
        memo: dict[tuple[str, ...], Any] = {}
        active: set[tuple[str, ...]] = set()
        resources = AsyncExitStack()
        owned: set[int] = set()
        root_dir = os.path.dirname(os.path.abspath(cfg_path))

        async def own(node):
            if isgenerator(node):
                node = resources.enter_context(contextmanager(lambda: node)())
            elif isasyncgen(node):
                node = await resources.enter_async_context(
                    asynccontextmanager(lambda: node)()
                )
            elif id(node) not in owned and callable(close := _get_close(node)):
                owned.add(id(node))

                async def cleanup():
                    result = close()
                    if isawaitable(result):
                        await result

                resources.push_async_callback(cleanup)
            return node

        async def reference(name):
            parts = tuple(name.split("."))
            current = cfg
            prefix: tuple[str, ...] = ()
            for part in parts:
                try:
                    if isinstance(current, dict):
                        current = current[part]
                    elif isinstance(current, list):
                        current = current[int(part)]
                    else:
                        break
                    prefix += (part,)
                except (KeyError, IndexError, ValueError):
                    break
            else:
                return await parse(current, parts, base_dir(parts))
            if not prefix:
                raise ConfigError(f"Can't resolve config item: {name}")
            resolved = await parse(current, prefix, base_dir(prefix))
            return _resolve_segments(resolved, parts[len(prefix) :], name)

        def base_dir(parts):
            current = cfg
            directory = root_dir
            for part in parts:
                if included := getattr(current, "__include_path__", None):
                    directory = os.path.dirname(included)
                current = (
                    current[int(part)] if isinstance(current, list) else current[part]
                )
            return directory

        async def parse(value, parts, directory):
            if parts in memo:
                return memo[parts]
            path = ".".join(parts)
            if parts in active:
                raise ConfigError(f"Circular config reference: {path}")
            active.add(parts)
            try:
                if included := getattr(value, "__include_path__", None):
                    directory = os.path.dirname(included)
                if isinstance(value, dict):
                    parsed = AttrDict()
                    for key, child in value.items():
                        parsed[key] = await parse(child, (*parts, str(key)), directory)
                    value = (
                        await self.get_node(parsed, path, collections, directory, own)
                        if parts
                        else parsed
                    )
                elif isinstance(value, list):
                    value = [
                        await parse(child, (*parts, str(i)), directory)
                        for i, child in enumerate(value)
                    ]
                    value = await self.get_node(
                        value, path, collections, directory, own
                    )
                elif isinstance(value, str):
                    if match := ENTITY_RE.fullmatch(value):
                        value = await reference(match.group(1))
                    elif LAZY_ITEM_RE.fullmatch(value):
                        value = LazyVar(value, path)
                    else:
                        value = validate_relative_path(value, directory)
                memo[parts] = value
                return value
            finally:
                active.remove(parts)

        try:
            tree = await parse(cfg, (), root_dir)
        except BaseException:
            await resources.aclose()
            raise
        return ConfigTree(tree, collections, resources)


class ConfigTree(AttrDict):
    def __init__(
        self,
        tree,
        collections: dict[str, AttrDict] | None = None,
        resources: AsyncExitStack | None = None,
    ):
        super().__init__(tree)
        self._collections = collections if collections is not None else {}
        self._resources = resources or AsyncExitStack()

    def get_collection(self, name: str):
        return self._collections.get(name)

    def get_collections(self):
        return dict(self._collections)

    async def close(self):
        await self._resources.aclose()


def _resolve_segments(value, segments, path):
    for segment in segments:
        try:
            if isinstance(value, dict):
                value = value[segment]
            elif isinstance(value, (list, tuple)):
                value = value[int(segment)]
            else:
                value = getattr(value, segment)
        except (KeyError, IndexError, ValueError, AttributeError) as error:
            raise ConfigError(f"Can't resolve {path} to value") from error
    return value


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
    if isinstance(rpc := cfg.get("rpc"), str) and "${" in rpc:
        raise ConfigError(f"{path}: set the RPC environment variable {rpc}")
    erc20 = cfg.pop("erc20", None)
    chain = await cls.connect(name=path.rsplit(".", 1)[-1], **cfg)
    try:
        if erc20:
            await asyncio.gather(
                *[chain.load_token(token, cache_as=key) for key, token in erc20.items()]
            )
    except BaseException:
        await chain.close()
        raise
    return chain


def _lazy_filter(cfg: Any, path: str) -> bool:
    if not isinstance(cfg, dict):
        return False

    def contains_lazy(value):
        if isinstance(value, str):
            return LAZY_ITEM_RE.fullmatch(value) is not None
        if isinstance(value, dict):
            return any(contains_lazy(child) for child in value.values())
        if isinstance(value, list):
            return any(contains_lazy(child) for child in value)
        return isinstance(value, Lazy) and not value.as_lazy

    if cfg.get(AS_LAZY_KEY, False) or cfg.get(AS_FACTORY_KEY, False):
        return True
    if IMPORT_KEY in cfg:
        return any(contains_lazy(value) for value in cfg.values())
    return any(
        isinstance(value, str) and LAZY_ITEM_RE.fullmatch(value) is not None
        for value in cfg.values()
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
        cfg = dict(cfg)
        self._as_lazy = cfg.pop(AS_LAZY_KEY, False)
        self._as_factory = cfg.pop(AS_FACTORY_KEY, False)

        self.cfg = cfg
        self.path = path
        self._resources = AsyncExitStack()

    @property
    def as_lazy(self):
        return self._as_lazy or self._as_factory

    @property
    def as_factory(self):
        return self._as_factory

    @property
    def type(self) -> type[T] | None:
        if (cached := getattr(self, "_cached", empty)) is not empty:
            return cast(type[T], type(cached))
        initializer = getattr(self, "cfg", {}).get(IMPORT_KEY)
        cls = load_path(initializer) if initializer else None
        return cls if isinstance(cls, type) else None

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

        return _resolve_segments(vars, filter(None, path.split(".")), path)

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

        async def resolve(value):
            if isinstance(value, str) and (match := LAZY_ITEM_RE.match(value)):
                value = self._resolve_path(match.group(1), vars)
            if isinstance(value, Lazy) and not value.as_lazy:
                return await value()
            if isinstance(value, dict):
                return {key: await resolve(child) for key, child in value.items()}
            if isinstance(value, list):
                return [await resolve(child) for child in value]
            return value

        kw = await resolve(kw)
        value = cast(T, await config_loader.get_node(kw, self.path))
        if isgenerator(value):
            generator = value
            value = self._resources.enter_context(contextmanager(lambda: generator)())
        elif isasyncgen(value):
            generator = value
            value = await self._resources.enter_async_context(
                asynccontextmanager(lambda: generator)()
            )
        elif callable(close := _get_close(value)):

            async def cleanup():
                result = close()
                if isawaitable(result):
                    await result

            self._resources.push_async_callback(cleanup)
        if not self.as_factory:
            self._set_cached(cast(T, value))
        return cast(T, value)

    async def close(self):
        resources = getattr(self, "_resources", None)
        if resources is not None:
            await resources.aclose()


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
