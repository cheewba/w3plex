"""Cross-version tests; all passwords and values are public test data."""

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from w3plex.security import LegacyContext

FIXTURES = Path(__file__).parent / "fixtures" / "legacy-security"


@pytest.mark.parametrize("n", [None, 4096, 8192, 16384, 32768])
def test_new_file_and_keystore_are_readable_by_frozen_baseline(tmp_path, n):
    store = tmp_path / "keystore.bin"
    master = "PUBLIC-TEST-master"
    if n is not None:
        manifest = json.loads((FIXTURES / "manifest.json").read_text())
        master = manifest["master_password"]
        store.write_bytes((FIXTURES / f"ks01-{n}.bin").read_bytes())
    replies = iter([master, master])
    encryption = LegacyContext(
        store, input_handler=lambda _: next(replies), compatibility=True
    )
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
            """import getpass, hashlib, runpy, sys
getpass.getpass = lambda _: sys.argv[3]
old = runpy.run_path(sys.argv[1])
if sys.argv[4] != "None":
    state = old["secure_open"].__globals__
    state["_SCRYPT_N"] = int(sys.argv[4])
    state["scrypt"] = lambda *args, **kwargs: hashlib.scrypt(*args, **kwargs, maxmem=128 * 1024 * 1024)
with old["secure_open"](sys.argv[2], "rb") as stream:
    assert stream.read() == b"PUBLIC-TEST-value\\r\\n"
""",
            str(FIXTURES / "baseline_reader.py"),
            str(output),
            master,
            str(n),
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
    assert (
        hashlib.sha256((FIXTURES / "baseline_reader.py").read_bytes()).hexdigest()
        == provenance["sha256"]
    )
