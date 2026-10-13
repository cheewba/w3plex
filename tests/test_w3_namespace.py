"""Opt-in consumers and compatibility imports share one implementation."""

import importlib

import pytest
import w3ext

from w3plex import w3


@pytest.mark.parametrize("name", ["Chain", "Token", "Currency", "CurrencyAmount"])
def test_unadapted_exports_keep_identity(name):
    assert getattr(w3, name) is getattr(w3ext, name)


@pytest.mark.parametrize(
    "name", ["signing", "transport", "rpc", "integrations", "settings", "files"]
)
def test_old_consumer_imports_alias_new_module(name):
    old = importlib.import_module(f"w3plex.security.{name}")
    new = importlib.import_module(f"w3plex.w3.{name}")
    assert old is new


def test_old_config_import_aliases_public_reader():
    from w3plex.config import reading
    from w3plex.security import config

    assert config is reading
