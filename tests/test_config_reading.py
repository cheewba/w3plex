"""YAML reads, environment expansion, includes and explicit file creation."""

import builtins
import os
import subprocess
import sys
from pathlib import Path

import pytest

from w3plex.config import create_config, load_config
from w3plex.main import load_config as load_cli_config
from w3plex.security import disable_encrypted_io


def test_fresh_security_import_has_no_global_effects(tmp_path):
    (tmp_path / ".env").write_text("TEST_SIDE_EFFECT=changed\n")
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """import builtins, os, sys
before = builtins.open
env = dict(os.environ)
import w3plex.security
assert builtins.open is before
assert os.environ == env
assert "w3plex.main" not in sys.modules
assert "w3plex.shell" not in sys.modules
""",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_config_opener_environment_and_nested_includes_are_explicit(
    tmp_path, monkeypatch
):
    calls = []
    monkeypatch.setenv("TEST_RPC", "host-value")
    (tmp_path / "config.yaml").write_text("child: !include child.yaml\n")
    (tmp_path / "child.yaml").write_text("leaf: !include leaf.yaml\n")
    (tmp_path / "leaf.yaml").write_text(
        "url: ${TEST_RPC}\nkey: 0x1234\nmissing: $UNSET\n"
    )

    def opener(filename, *args, **kwargs):
        calls.append(Path(filename))
        return open(filename, *args, **kwargs)

    value = load_config(
        tmp_path / "config.yaml",
        opener=opener,
        environment={"TEST_RPC": "explicit-value"},
    )
    assert value["child"]["leaf"] == {
        "url": "explicit-value",
        "key": "0x1234",
        "missing": "$UNSET",
    }
    assert calls == [
        tmp_path / name for name in ("config.yaml", "child.yaml", "leaf.yaml")
    ]
    assert os.environ["TEST_RPC"] == "host-value"
    target = tmp_path / "new.yaml"
    assert (
        create_config(target, {"url": "https://offline.example"}, opener=opener)
        == target
    )
    original = target.read_bytes()
    with pytest.raises(FileExistsError):
        create_config(target, {"url": "replacement"}, opener=opener)
    assert target.read_bytes() == original
    (tmp_path / "list.yaml").write_text("- list\n")
    with pytest.raises(TypeError, match="mapping"):
        load_config(tmp_path / "list.yaml", opener=opener, environment={})


@pytest.fixture(autouse=True)
def restore_global_opener():
    previous = builtins.open
    yield
    if builtins.open is not previous:
        disable_encrypted_io()
    assert builtins.open is previous


def test_cli_config_expands_variables_in_nested_includes(tmp_path, monkeypatch):
    monkeypatch.setenv("PUBLIC_CONFIG_TEST", "expanded")
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "child.yaml").write_text("value: ${PUBLIC_CONFIG_TEST}\n")
    root = tmp_path / "w3plex.yaml"
    root.write_text(
        "value: $PUBLIC_CONFIG_TEST\n"
        "missing: ${PUBLIC_CONFIG_UNSET}\n"
        "child: !include nested/child.yaml\n"
    )
    result = load_cli_config(str(root))
    assert result["value"] == "expanded"
    assert result["missing"] == "${PUBLIC_CONFIG_UNSET}"
    assert result["child"]["value"] == "expanded"
    assert result["child"].__include_path__ == str(nested / "child.yaml")


@pytest.mark.parametrize("content", ["", "- item\n", "value\n"])
def test_cli_config_requires_a_mapping(tmp_path, content):
    root = tmp_path / "w3plex.yaml"
    root.write_text(content)
    with pytest.raises(TypeError, match="Config must be a YAML mapping"):
        load_cli_config(str(root))
