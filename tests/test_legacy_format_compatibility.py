"""Cross-version tests; all passwords and values are public test data."""

import hashlib
import builtins
import importlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures" / "legacy-security"


@pytest.fixture
def encryption():
    previous = builtins.open
    try:
        return importlib.import_module("w3plex.secure")
    finally:
        builtins.open = previous


def test_new_file_and_keystore_are_readable_by_frozen_baseline(tmp_path, monkeypatch, encryption):
    store = tmp_path / "keystore.bin"
    monkeypatch.setattr(encryption, "_KEYSTORE_PATH", store)
    monkeypatch.setattr(encryption, "_salt", None)
    monkeypatch.setattr(encryption, "_master_key", None)
    monkeypatch.setattr(encryption, "_SCRYPT_WORK", None)
    replies = iter(["PUBLIC-TEST-master", "PUBLIC-TEST-master"])
    monkeypatch.setattr(encryption.getpass, "getpass", lambda _: next(replies))
    source = tmp_path / "input.txt"
    source.write_text("PUBLIC-TEST-value\r\n", encoding="utf-8", newline="")
    output = encryption.encrypt_file(
        source, password="PUBLIC-TEST-file", add_to_keystore=True
    )
    before = (output.read_bytes(), store.read_bytes())
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """import getpass, runpy, sys
getpass.getpass = lambda _: "PUBLIC-TEST-master"
old = runpy.run_path(sys.argv[1])
with old["secure_open"](sys.argv[2], "rb") as stream:
    assert stream.read() == b"PUBLIC-TEST-value\\r\\n"
""",
            str(FIXTURES / "baseline_reader.py"),
            str(output),
        ],
        env={**os.environ, "W3PLEX_KEYSTORE": str(store)},
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert (output.read_bytes(), store.read_bytes()) == before


def test_frozen_baseline_reader_matches_recorded_provenance():
    provenance = json.loads((FIXTURES / "baseline-reader.json").read_text())
    assert provenance["revision"] == "d3a88e1"
    assert hashlib.sha256((FIXTURES / "baseline_reader.py").read_bytes()).hexdigest() == provenance["sha256"]
