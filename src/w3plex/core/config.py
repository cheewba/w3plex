import asyncio
import os
import re
from collections import defaultdict
from inspect import isclass
from typing import Dict, Optional, Callable, Type, TypeVar, overload, Any, Union

from lazyplex import as_future, Application
from w3ext import Chain

from .objects import EntityConfig, Entity, Service, Loader, Filter, Condition
from ..utils import load_path, AttrDict
from ..exceptions import ConfigError


__all__ = ['config_loader', 'ConfigTree']

T = TypeVar("T")

COLLECTIONS = (
    ('chains', Chain),
    ('services', Service),
    ('filters', Filter),
    ('loaders', Loader),
    ('conditions', Condition),
)

IMPORT_KEY = '__init__'
IMPORT_SIGN = '$'


def validate_relative_path(path, root=None):
    if not root or not isinstance(path, str):
        return path

    if not os.path.isabs(path):
        joined_path = os.path.join(root, path)
        if os.path.exists(joined_path):
            return joined_path
    return path


def validate_relative_import(path, root=None):
    if (not root
            or not isinstance(path, str)
            or not path.startswith('.')):
        return path

    level_up = len(path) - len(path.lstrip('.')) - 1
    base_components = root.split('/')
    if level_up <= len(base_components):
        base_components = base_components[:len(base_components) - level_up]
    else:
        raise ValueError(f"Too many leading dots in '{path}' "
                         f"for the given base path '{root}'")

    relative_import = path[level_up + 1:]
    full_import = '.'.join(base_components + relative_import.split('.'))
    return full_import.rstrip('.')


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

    def get_unresolved(self) -> bool:
        return list(self._later.keys())


class _ConfigLoader:
    def __init__(self) -> None:
        self._filters = []

    @overload
    def add_node(
        self,
        flt: Callable[[Dict, str], bool],
        collection: Optional[Union[str, Callable[[Any], str]]] = None
    ) -> Callable[[Callable[['EntityConfig', str], 'Entity']], None]: ...

    def add_node(
        self, flt: str,
        collection: Optional[Union[str, Callable[[Any], str]]] = None
    ) -> Callable[[Callable[['EntityConfig', str], 'Entity']], None]:
        def inner(fn: Callable[['EntityConfig', str], 'Entity']):
            nonlocal flt
            if not isinstance(flt, Callable):
                flt = self._regexp_flt(flt)
            self._filters.append([flt, fn, collection])
            return fn
        return inner

    def _regexp_flt(self, regexp: str):
        _regexp = re.compile(regexp)
        def _filter(cfg: dict, path: str) -> bool:
            return _regexp.match(path) is not None
        return _filter

    async def _get_node(
        self, cfg: Dict, path: str, collections: Optional[defaultdict],
        relative_path: Optional[str] = None
    ) -> Optional[Callable[['EntityConfig', str], 'Entity']]:
        for flt, node, collection in self._filters[::-1]:
            # check filters as LIFO
            if (flt(cfg, path)):
                try:
                    node = await as_future(node(cfg, path))
                    if node and collection:
                        if isinstance(collection, Callable):
                            collection = collection(node)
                        collections[collection][path.rsplit('.', 1)[-1]] = node
                    return node
                except SkipNode:
                    continue
        return cfg

    async def parse(self, cfg: Dict, cfg_path: str) -> "ConfigTree":
        unresolved_states = []

        def get_node_rel_path(node, root_path: str) -> str:
            child = getattr(node, '__include_path__', None)
            return os.path.relpath(os.path.dirname(child), root_path) if child else None

        def _resolve(collection, value, key, state):
            def callback(val):
                collection[key] = val
                state['unresolved'] -= 1

            if isinstance(value, str) and value.startswith(IMPORT_SIGN):
                state['unresolved'] += 1
                resolver.resolve_once_ready(value[len(IMPORT_SIGN):], callback)

        async def _parse_item(key, value, state, path, relative_path):
            if isinstance(value, dict):
                value_path = ".".join([path, str(key)]) if path else str(key)
                entity = await _parse_cfg(
                    value, value_path, collections,
                    get_node_rel_path(value, relative_path) or relative_path
                )
                if entity:
                    if not isinstance(entity, dict):
                        resolver.register(value_path, entity)
                    value = entity
            elif isinstance(value, list):
                parsed = []
                for i, item in enumerate(value):
                    parsed.append(await _parse_item(i, item, state, path, relative_path))
                    _resolve(value, item, i, state)
                value = parsed
            elif isinstance(value, str):
                _resolve(state['parsed'], value, key, state)

            return value

        async def _parse_cfg(cfg: Dict, path: str = "",
                             collections: Optional[defaultdict] = None,
                             relative_path: Optional[str] = None) -> Optional[Dict]:
            if collections is None:
                collections = defaultdict(list)
            state = {'parsed': (parsed := AttrDict()), 'unresolved': 0, 'path': path}
            for key, value in cfg.items():
                value = await _parse_item(key, value, state, path, relative_path)
                if key not in parsed:
                    value = validate_relative_path(value, relative_path)
                    value = validate_relative_import(value, relative_path)
                    parsed[key] = value

            if state["unresolved"] == 0:
                return await self._get_node(parsed, path, collections, relative_path)

            unresolved_states.append(state)
            return None

        resolver = _Resolver()
        parsed = await _parse_cfg(cfg, "", collections := defaultdict(AttrDict),
                                  get_node_rel_path(cfg, os.path.dirname(cfg_path)))

        unresolved = resolver.get_unresolved()
        while True:
            i = 0
            while i < len(unresolved_states):
                state = unresolved_states[i]
                if state['unresolved'] == 0:
                    path = state['path'].split('.')
                    parent = parsed
                    for item in path[:-1]:
                        parent = parent[item]
                    parent[path[-1]] = await self._get_node(
                        state['parsed'], state['path'], collections
                    )
                    unresolved_states.pop(i)
                    continue
                i += 1
            if unresolved == resolver.get_unresolved():
                break

        if (unresolved := resolver.get_unresolved()):
            raise ConfigError(f"Can't resolve config items: {', '.join(unresolved)}")

        return ConfigTree(parsed, collections)


class ConfigTree(AttrDict):
    def __init__(self, tree, collections: Optional[Dict[str, list]]):
        super().__init__(tree)

        self._collections = collections

    def __getattr__(self, name: str) -> Any:
        if name.startswith('get_'):
            collection = self._collections.get(name[4:])
            return lambda: collection
        return super().__getattr__(name)

    async def close(self):
        pass


config_loader = _ConfigLoader()


def _entity_filter(cfg: Dict, path: str) -> bool:
    return IMPORT_KEY in cfg


def _get_entity_collection(entity: Entity) -> str:
    for collection, cls in COLLECTIONS:
        if isinstance(entity, cls):
            return collection
    return ""


@config_loader.add_node(_entity_filter, _get_entity_collection)
async def entity_factory(cfg: 'EntityConfig', path: str) -> 'Entity':
    conf = dict(cfg)  # create a copy to modify it
    init_path = conf.pop(IMPORT_KEY)
    init = load_path(init_path)
    if isclass(init) and issubclass(init, Chain):
        return await load_chain(cfg, path, init)
    if isinstance(init, Application):
        # for application there's another protocol
        raise SkipNode

    loaded = await as_future(init(**conf))
    if isinstance(loaded, Service):
        await loaded.init()
    return loaded


@overload
async def load_chain(cfg: 'EntityConfig', path: str) -> Chain: ...

@config_loader.add_node(r'^chains\.[^.]+$', 'chains')  # default location for chains in config file
async def load_chain(cfg: 'EntityConfig', path: str, cls: Optional[Type[T]] = None) -> T:
    cls = cls or Chain
    erc20 = cfg.pop('erc20', None)
    chain = await cls.connect(name=path.rsplit('.', 1)[-1], **cfg)
    if (erc20):
        await asyncio.gather(*[chain.load_token(token, cache_as=key)
                                for key, token in erc20.items()])
    return chain