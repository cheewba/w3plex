import asyncio
import io
from types import SimpleNamespace

import pytest
from lazyplex import create_context
from lazyplex.core.context import branch
from ruamel import yaml
from w3ext import Chain, Currency

from w3plex.config.config import (
    ConfigTree,
    Lazy,
    LazyVar,
    config_loader,
    entity_factory,
)
from w3plex.config.yaml import Loader
from w3plex.constants import CONTEXT_LOGGER_KEY
from w3plex.core.objects import application
from w3plex.exceptions import ConfigError
from w3plex.runner import Runner


def test_config_node_registration_accepts_non_mapping_values(tmp_path):
    loader = config_loader.clone()

    @loader.add_node(r"^logging$")
    def loggers(config, path):
        return tuple(config)

    tree = asyncio.run(
        loader.parse({"logging": ["console"]}, str(tmp_path / "config.yaml"))
    )
    assert tree.logging == ("console",)


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
    calls = []

    def value():
        calls.append("created")
        return 0

    monkeypatch.setattr("w3plex.config.config.load_path", lambda path: value)
    lazy = Lazy[int]({"__init__": "fixture:value"}, "value")
    with create_context({"application": "test"}), branch({"action": "test"}):
        assert asyncio.run(lazy()) == 0
        assert asyncio.run(lazy()) == 0
    assert calls == ["created"]


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


def test_config_resolves_dependency_chains_lists_and_attributes(tmp_path):
    cfg = {
        "values": ["$second", "$plain.answer", "$first.value"],
        "second": {"__init__": "types:SimpleNamespace", "value": "$first"},
        "first": {"__init__": "types:SimpleNamespace", "value": 42},
        "plain": {"answer": 7},
    }
    tree = asyncio.run(config_loader.parse(cfg, str(tmp_path / "config.yaml")))
    assert tree["values"] == [tree.second, 7, 42]
    assert tree.second.value is tree.first
    assert cfg["values"][0] == "$second"
    assert cfg["first"]["__init__"] == "types:SimpleNamespace"


def test_config_reports_reference_cycles(tmp_path):
    with pytest.raises(ConfigError, match="Circular"):
        asyncio.run(
            config_loader.parse({"a": "$b", "b": "$a"}, str(tmp_path / "config.yaml"))
        )


@pytest.mark.parametrize("failure", [False, True])
def test_config_closes_generator_resources_on_exit_or_parse_failure(tmp_path, failure):
    loader = config_loader.clone()
    events = []

    @loader.add_node(r"^resource$", "resources")
    async def resource(cfg, path):
        events.append("open")
        try:
            yield SimpleNamespace(value=42)
        finally:
            events.append("close")

    async def check():
        cfg = {"resource": {}}
        if failure:
            cfg["missing"] = "$absent"
            with pytest.raises(ConfigError):
                await loader.parse(cfg, str(tmp_path / "config.yaml"))
        else:
            tree = await loader.parse(cfg, str(tmp_path / "config.yaml"))
            assert tree.resource.value == 42
            assert tree.get_collection("resources")["resource"] is tree.resource
            await tree.close()
            await tree.close()

    asyncio.run(check())
    assert events == ["open", "close"]


def test_nested_yaml_includes_use_each_files_directory(tmp_path):
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "wallets.yaml").write_text("file: wallets.txt\n")
    (nested / "app.yaml").write_text("wallets: !include wallets.yaml\n")
    stream = io.StringIO("app: !include nested/app.yaml\n")
    stream.name = str(tmp_path / "config.yaml")
    with pytest.warns(PendingDeprecationWarning):
        loaded = yaml.load(stream, Loader=Loader)
    assert loaded["app"]["wallets"]["file"] == "wallets.txt"
    assert loaded["app"]["wallets"].__include_path__ == str(nested / "wallets.yaml")


def test_lazy_resolves_attributes_and_sequence_indices():
    variable = LazyVar("$.context.item.values.0.answer", "value")
    with create_context({"item": SimpleNamespace(values=[{"answer": 42}])}):
        assert asyncio.run(variable()) == 42
    with (
        create_context({"item": SimpleNamespace()}),
        pytest.raises(ConfigError, match="missing"),
    ):
        asyncio.run(LazyVar("$.context.item.missing", "value")())


def test_runners_isolate_factories_apply_aliases_and_keep_cli_overrides(
    tmp_path, monkeypatch
):
    @application
    async def sample(action, items=None, **config):
        yield items or [1]

    @sample.action("show", default=True)
    async def show(item, message="default", **config):
        return item, message

    monkeypatch.setattr("w3plex.runner.load_path", lambda path: sample)
    cfg = {
        "applications": {
            "sample": {
                "__init__": "test:sample",
                "actions": {"alias": {"action": "show", "message": "config"}},
            }
        }
    }

    async def check():
        first, second = Runner(), Runner()
        await first.init(cfg, str(tmp_path / "config.yaml"))
        await second.init(cfg, str(tmp_path / "config.yaml"))
        try:
            assert await first.tree.applications.sample("alias") == [[1, "config"]]
            assert await second.tree.applications.sample(
                "alias", message="with spaces"
            ) == [[1, "with spaces"]]
            with pytest.raises(ValueError, match="Unknown action"):
                first.tree.applications.sample("missing")
        finally:
            await first.finalize()
            await second.finalize()
        with pytest.raises(RuntimeError, match="not initialized"):
            _ = first.tree
        await first.finalize()

    asyncio.run(check())


def test_runner_rejects_blocking_call_on_its_running_loop():
    async def check():
        runner = Runner()
        with pytest.raises(RuntimeError, match="Use await"):
            runner.blocking_call(asyncio.sleep(0))

    asyncio.run(check())


def test_context_dependent_config_resolves_per_action(tmp_path, monkeypatch):
    @application
    async def sample(action, **config):
        yield [1, 2]

    @sample.action("show", default=True)
    async def show(item, deferred, direct, **config):
        return deferred.value, direct

    monkeypatch.setattr("w3plex.runner.load_path", lambda path: sample)
    cfg = {
        "applications": {
            "sample": {
                "__init__": "test:sample",
                "actions": {
                    "show": {
                        "deferred": {
                            "__init__": "types:SimpleNamespace",
                            "value": "$.context.item",
                        },
                        "direct": "$.context.item",
                    }
                },
            }
        }
    }

    async def check():
        runner = Runner()
        try:
            await runner.init(cfg, str(tmp_path / "config.yaml"))
            assert await runner.tree.applications.sample() == [[1, 1], [2, 2]]
        finally:
            await runner.finalize()

    asyncio.run(check())


def test_applications_treat_text_items_and_results_as_complete_values():
    @application
    async def sample(action, **config):
        yield "Alice"

    @sample.action("greet", default=True)
    async def greet(name, **config):
        return f"Hello, {name}!"

    assert asyncio.run(sample()) == ["Hello, Alice!"]
