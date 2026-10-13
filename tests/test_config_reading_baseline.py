"""Characterize CLI config reads before connecting the shared library reader."""

import pytest

from w3plex.main import load_config


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
    result = load_config(str(root))
    assert result["value"] == "expanded"
    assert result["missing"] == "${PUBLIC_CONFIG_UNSET}"
    assert result["child"]["value"] == "expanded"
    assert result["child"].__include_path__ == str(nested / "child.yaml")


@pytest.mark.parametrize("content", ["", "- item\n", "value\n"])
def test_cli_config_requires_a_mapping(tmp_path, content):
    root = tmp_path / "w3plex.yaml"
    root.write_text(content)
    with pytest.raises(TypeError, match="Config must be a YAML mapping"):
        load_config(str(root))
