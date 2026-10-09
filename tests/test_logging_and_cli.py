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
    assert "{init}" in result.stdout
