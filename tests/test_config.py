import asyncio
import io
from types import SimpleNamespace

import pytest
from lazyplex import ContextScope, create_context
from lazyplex.core.context import branch
from ruamel import yaml
from w3ext import Chain, Currency

from w3plex.config.config import (
    ConfigTree,
    Lazy,
    LazyVar,
    _ConfigLoader,
    _Resolver,
    config_loader,
    entity_factory,
)
from w3plex.config.yaml import Loader
from w3plex.constants import CONTEXT_LOGGER_KEY
from w3plex.core.objects import application
from w3plex.exceptions import ConfigError
from w3plex.runner import Runner


def test_resolver_reports_pending_names_and_resolves_callbacks():
    resolver = _Resolver()
    results = []
    assert not resolver.resolve_once_ready("item", results.append)
    assert resolver.get_unresolved() == ["item"]
    resolver.register("item", 42)
    assert results == [42]
    assert resolver.get_unresolved() == []


def test_config_node_registration_accepts_non_mapping_values():
    loader = _ConfigLoader()

    @loader.add_node(r"^logging$")
    def loggers(config, path):
        return tuple(config)

    assert asyncio.run(loader.get_node(["console"], "logging")) == ("console",)


@pytest.mark.parametrize("reference_first", [False, True])
def test_config_resolves_references_and_plain_values(tmp_path, reference_first):
    entries = [
        ("item", {"__init__": "types:SimpleNamespace", "value": 42}),
        ("reference", "$item"),
    ]
    if reference_first:
        entries.reverse()
    config = dict(entries, label="plain", count=3)
    tree = asyncio.run(config_loader.parse(config, str(tmp_path / "config.yaml")))
    assert isinstance(tree.item, SimpleNamespace)
    assert tree.reference is tree.item
    assert tree.label == "plain"
    assert tree.count == 3


def test_config_reports_unresolved_references(tmp_path):
    with pytest.raises(ConfigError, match="missing"):
        asyncio.run(
            config_loader.parse({"ref": "$missing"}, str(tmp_path / "config.yaml"))
        )


def test_chain_entity_factory_connects_once_and_removes_initializer(monkeypatch):
    calls = []

    class FakeChain(Chain):
        @classmethod
        async def connect(cls, **config):
            calls.append(config)
            return cls(
                config["chain_id"], Currency("Ether", "ETH", 18), name=config["name"]
            )

    monkeypatch.setattr("w3plex.config.config.load_path", lambda path: FakeChain)
    chain = asyncio.run(
        entity_factory({"__init__": "custom:Chain", "chain_id": 1}, "custom.chain")
    )
    assert isinstance(chain, FakeChain)
    assert calls == [{"chain_id": 1, "name": "chain"}]


def test_yaml_include_subset_retains_path_and_returns_mapping(tmp_path):
    included = tmp_path / "chains.yaml"
    included.write_text("ethereum:\n  chain_id: 1\npolygon:\n  chain_id: 137\n")
    stream = io.StringIO("chains: !include\n  file: chains.yaml\n  items: [ethereum]\n")
    stream.name = str(tmp_path / "config.yaml")
    with pytest.warns(PendingDeprecationWarning, match="load will be removed"):
        loaded = yaml.load(stream, Loader=Loader)
    assert dict(loaded["chains"]) == {"ethereum": {"chain_id": 1}}
    assert loaded["chains"].__include_path__ == str(included)


def test_lazy_action_cache_keeps_falsy_values(monkeypatch):
    monkeypatch.setattr("w3plex.config.config.get_scope", lambda: ContextScope.action)
    lazy = Lazy[int]({}, "value")
    with create_context({"application": "test"}), branch({"action": "test"}):
        lazy._set_cached(0)
        assert asyncio.run(lazy()) == 0


def test_lazy_variable_reports_invalid_reference():
    variable = LazyVar("invalid", "variable")
    with (
        create_context({"application": "test"}),
        pytest.raises(ConfigError, match="Invalid lazy variable"),
    ):
        asyncio.run(variable())


def test_config_tree_defaults_to_empty_collections():
    tree = ConfigTree({"value": 42})
    assert tree.get_collections() == {}
    assert tree.get_collection("chains") is None


def test_runner_tree_requires_initialization():
    async def check():
        runner = Runner()
        with pytest.raises(RuntimeError, match="not initialized"):
            _ = runner.tree

    asyncio.run(check())


def test_application_context_returns_context_with_bound_logger():
    @application
    async def sample():
        return 42

    context = {}
    result = asyncio.run(sample.update_application_context(context))
    assert result is context
    assert CONTEXT_LOGGER_KEY in context
