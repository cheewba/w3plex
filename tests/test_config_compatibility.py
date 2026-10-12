"""Extra config and CLI characterization before source edits."""

import subprocess
import sys


def run(tmp_path, source):
    result = subprocess.run(
        [sys.executable, "-c", source],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_nested_relative_includes_environment_hex_and_mapping_error(tmp_path):
    run(
        tmp_path,
        """import os
from pathlib import Path
from w3plex.main import load_config
Path("nested").mkdir()
Path("config.yaml").write_text("root: !include nested/child.yaml\\n")
Path("nested/child.yaml").write_text("leaf: !include leaf.yaml\\n")
Path("nested/leaf.yaml").write_text("url: ${TEST_RPC}\\nkey: 0x1234\\nmissing: $UNDEFINED_VARIABLE\\n")
os.environ["TEST_RPC"] = "https://offline.example"
cfg = load_config("config.yaml")
assert cfg["root"]["leaf"]["url"] == "https://offline.example"
assert cfg["root"]["leaf"]["key"] == "0x1234"
assert cfg["root"]["leaf"]["missing"] == "$UNDEFINED_VARIABLE"
assert cfg["root"]["leaf"].__include_path__ == str(Path("nested/leaf.yaml").absolute())
Path("bad.yaml").write_text("- list\\n")
try:
    load_config("bad.yaml")
except TypeError as error:
    assert "mapping" in str(error)
else:
    raise AssertionError("mapping required")
""",
    )


def test_init_preserves_existing_companion_files(tmp_path):
    run(
        tmp_path,
        """from pathlib import Path
from w3plex.main import process_args
Path("chains.yaml").write_text("existing chains\\n")
Path("wallets.txt").write_text("existing wallets\\n")
assert process_args(["init"]) is None
assert Path("chains.yaml").read_text() == "existing chains\\n"
assert Path("wallets.txt").read_text() == "existing wallets\\n"
""",
    )


def test_cli_cancel_exit_code_without_traceback(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """import w3plex.main as cli
def cancel():
    raise KeyboardInterrupt()
cli.process_args = cancel
cli.main()
""",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 130
    assert "cancelled" in result.stderr
    assert "Traceback" not in result.stderr
