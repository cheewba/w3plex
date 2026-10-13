"""SDK exports stay compatible; experimental application policy moved out."""

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
def test_application_policy_is_absent_from_library_namespace(name):
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module(f"w3plex.security.{name}")
