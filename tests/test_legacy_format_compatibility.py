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


@pytest.fixture(scope="module")
def baseline_python():
    executable = os.environ.get("W3PLEX_BASELINE_PYTHON", sys.executable)
    if "W3PLEX_BASELINE_PYTHON" in os.environ:
        result = subprocess.run(
            [
                executable,
                "-I",
                "-c",
                """import importlib.util, json, sys
from importlib.metadata import version
print(json.dumps({
    "prefix": sys.prefix,
    "w3plex": importlib.util.find_spec("w3plex") is not None,
    "cryptopal": importlib.util.find_spec("cryptopal") is not None,
    "cryptography": version("cryptography"),
}))
""",
            ],
            env={},
            capture_output=True,
            text=True,
            timeout=20,
            check=True,
        )
        report = json.loads(result.stdout)
        assert Path(report["prefix"]).resolve() != Path(sys.prefix).resolve()
        assert not report["w3plex"] and not report["cryptopal"]
        assert report["cryptography"]
    return executable


def test_configured_baseline_environment_is_separate(baseline_python):
    if "W3PLEX_BASELINE_PYTHON" not in os.environ:
        pytest.skip("Set W3PLEX_BASELINE_PYTHON for separate-environment acceptance")
    assert Path(baseline_python).is_file()


@pytest.mark.parametrize("n", [None, 4096, 8192, 16384, 32768])
def test_new_file_and_keystore_are_readable_by_frozen_baseline(
    tmp_path, n, baseline_python
):
    store = tmp_path / "keystore.bin"
    master = "PUBLIC-TEST-master"
    if n is not None:
        manifest = json.loads((FIXTURES / "manifest.json").read_text())
        master = manifest["master_password"]
        store.write_bytes((FIXTURES / f"ks01-{n}.bin").read_bytes())
    replies = iter([master, master])
    encryption = LegacyContext(
        store, input_handler=lambda _: next(replies), persist_keys=True
    )
    source = tmp_path / "input.txt"
    source.write_text("PUBLIC-TEST-value\r\n", encoding="utf-8", newline="")
    output = encryption.encrypt_file(
        source, password="PUBLIC-TEST-file", add_to_keystore=True
    )
    before = (output.read_bytes(), store.read_bytes())
    result = subprocess.run(
        [
            baseline_python,
            "-I",
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
        env={"W3PLEX_KEYSTORE": str(store)},
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert (output.read_bytes(), store.read_bytes()) == before


@pytest.mark.parametrize("n", [4096, 8192, 16384, 32768])
def test_frozen_baseline_reads_fixed_old_files_without_rewriting(
    tmp_path, n, baseline_python
):
    manifest = json.loads((FIXTURES / "manifest.json").read_text())
    store = tmp_path / "old-store.bin"
    store.write_bytes((FIXTURES / f"ks01-{n}.bin").read_bytes())
    source = FIXTURES / "sample.enc"
    before = (source.read_bytes(), store.read_bytes())
    result = subprocess.run(
        [
            baseline_python,
            "-I",
            "-c",
            """import getpass, hashlib, runpy, sys
getpass.getpass = lambda _: sys.argv[3]
old = runpy.run_path(sys.argv[1])
state = old["secure_open"].__globals__
state["_SCRYPT_N"] = int(sys.argv[4])
state["scrypt"] = lambda *args, **kwargs: hashlib.scrypt(*args, **kwargs, maxmem=128 * 1024 * 1024)
with old["secure_open"](sys.argv[2], "rb") as stream:
    assert stream.read() == bytes.fromhex(sys.argv[5])
""",
            str(FIXTURES / "baseline_reader.py"),
            str(source),
            manifest["master_password"],
            str(n),
            manifest["plaintext_hex"],
        ],
        env={"W3PLEX_KEYSTORE": str(store)},
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert (source.read_bytes(), store.read_bytes()) == before


def test_frozen_baseline_reader_matches_recorded_provenance():
    provenance = json.loads((FIXTURES / "baseline-reader.json").read_text())
    assert provenance["revision"] == "d3a88e1"
    assert (
        hashlib.sha256((FIXTURES / "baseline_reader.py").read_bytes()).hexdigest()
        == provenance["sha256"]
    )
