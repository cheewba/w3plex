import subprocess
import sys

from loguru import logger as base_logger

from w3plex.log import Logger


def test_exception_logging_captures_traceback():
    records = []
    sink = base_logger.add(lambda message: records.append(message.record))
    logger = Logger(base_logger)
    try:
        try:
            raise ValueError("failure")
        except ValueError:
            logger.exception("task failed")
    finally:
        base_logger.remove(sink)

    assert len(records) == 1
    assert records[0]["level"].name == "ERROR"
    assert records[0]["message"] == "task failed"
    assert records[0]["exception"].type is ValueError
    assert records[0]["exception"].traceback is not None


def test_cli_reports_errors_to_stderr():
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import w3plex.main as cli\n"
                "def fail():\n"
                "    raise ValueError('application failed')\n"
                "cli.process_args = fail\n"
                "cli.main()\n"
            ),
        ],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert result.returncode == 1
    assert "application failed" in result.stderr
    assert "Traceback" not in result.stderr


def test_cli_help_works_without_config(tmp_path):
    result = subprocess.run(
        [sys.executable, "-m", "w3plex.main", "--help"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert result.returncode == 0
    assert "w3plex actions:" in result.stdout
    assert "{init,shell,encrypt,decrypt}" in result.stdout


def run_cli(tmp_path, *args):
    return subprocess.run(
        [sys.executable, "-m", "w3plex.main", *args],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )


def test_cli_init_creates_usable_config_and_preserves_existing_files(tmp_path):
    config = tmp_path / "project" / "my config.yaml"
    result = run_cli(tmp_path, "init", "--config", str(config))
    assert result.returncode == 0, result.stderr
    assert "__init__: w3plex.apps.balance:balance" in config.read_text()
    assert "items:" in config.read_text()
    assert (config.parent / "wallets.txt").exists()
    assert "${ETH_RPC_URL}" in (config.parent / "chains.yaml").read_text()
    original = config.read_text()
    result = run_cli(tmp_path, "init", "--config", str(config))
    assert result.returncode == 1
    assert "already exists" in result.stderr
    assert config.read_text() == original


def test_cli_encrypt_decrypt_absolute_paths_with_spaces_without_config(tmp_path):
    source = tmp_path / "file with spaces.txt"
    source.write_text("hello\n")
    result = run_cli(tmp_path, "encrypt", str(source), "--password", "test password")
    assert result.returncode == 0, result.stderr
    encrypted = source.with_suffix(".txt.enc")
    assert encrypted.read_bytes().startswith(b"ENC1")
    destination = tmp_path / "decoded.txt"
    result = run_cli(
        tmp_path,
        "decrypt",
        str(encrypted),
        "--password",
        "test password",
        "--output",
        str(destination),
    )
    assert result.returncode == 0, result.stderr
    assert destination.read_text() == "hello\n"


def test_cli_preserves_quoted_values_and_parses_typed_overrides(tmp_path):
    (tmp_path / "sample.py").write_text("""from w3plex import application
@application
async def sample(action, **config):
    yield [1]
@sample.action("show", default=True)
async def show(item, message, enabled, count, values, **config):
    assert message == "hello world"
    assert enabled is False
    assert count == 2
    assert values == [1, 2]
    print("arguments verified")
""")
    config = tmp_path / "config with spaces.yaml"
    config.write_text(
        "applications:\n  sample:\n    __init__: sample:sample\n    actions:\n      alias:\n        action: show\n        message: default\n"
    )
    result = run_cli(
        tmp_path,
        "--config",
        str(config),
        "sample",
        "alias",
        "message=hello world",
        "enabled=false",
        "count=2",
        "values=[1, 2]",
    )
    assert result.returncode == 0, result.stderr
    assert "arguments verified" in result.stdout


def test_logger_set_level_filters_messages():
    records = []
    sink = base_logger.add(lambda message: records.append(message.record))
    logger = Logger(base_logger)
    try:
        logger.setLevel("WARNING")
        logger.info("hidden")
        logger.log(20, "also hidden")
        logger.warning("visible")
    finally:
        base_logger.remove(sink)
    assert [record["message"] for record in records] == ["visible"]


def test_generated_balance_config_runs_with_mocked_rpc_and_closes_chain(tmp_path):
    script = """from pathlib import Path
from unittest.mock import AsyncMock
from w3ext import Chain, Currency
Path(".env").write_text("ETH_RPC_URL=https://offline.example\\n")
from w3plex.main import process_args
process_args(["init"])
assert "${ETH_RPC_URL}" in Path("chains.yaml").read_text()
Path("wallets.txt").write_text("# Test address\\n0x0000000000000000000000000000000000000001\\n")
chain = Chain(1, Currency("Ether", "ETH", 18), name="ethereum")
chain.get_balance = AsyncMock(return_value=chain.currency(2))
chain.close = AsyncMock()
Chain.connect = AsyncMock(return_value=chain)
process_args(["balance", "onchain"])
assert Chain.connect.await_args.kwargs["rpc"] == "https://offline.example"
assert chain.get_balance.await_count == 1
assert chain.close.await_count == 1
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "2 ETH" in result.stdout
