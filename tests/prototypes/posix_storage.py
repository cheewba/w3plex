"""POSIX file capability check without third-party or platform-specific wheels."""

import importlib
import json
import os
import platform
import stat
import sys
import tempfile
import types
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[2] / "src/w3plex/security"
package = types.ModuleType("storage_control_probe")
package.__path__ = [str(SOURCE)]
sys.modules[package.__name__] = package
storage = importlib.import_module(package.__name__ + ".storage")
FIXTURE = Path(__file__).resolve().parents[1] / "fixtures/vault-v1/sample.vault"


def main():
    raw = FIXTURE.read_bytes()
    with tempfile.TemporaryDirectory(prefix="cryptopal-storage-") as directory:
        private = Path(directory).resolve() / "private"
        private.mkdir(mode=0o700)
        with storage.CiphertextFile(private / "vault") as file:
            identity = file.write(raw, expected=None)
            assert file.read() == (raw, identity)
            assert stat.S_IMODE(file.path.stat().st_mode) == 0o600
            refused = False
            with file._writer():
                try:
                    file.write(raw, expected=identity)
                except storage.WriterBusy:
                    refused = True
            assert refused
            os.link(file.path, private / "alias")
            refused = False
            try:
                file.read()
            except storage.UnsafeStorage:
                refused = True
            assert refused
            (private / "alias").unlink()
            identity = file.write(raw, expected=file.read()[1])
            assert file.read() == (raw, identity)
            assert not list(private.glob("*.tmp"))
    print(
        json.dumps(
            {
                "platform": platform.platform(),
                "python": platform.python_version(),
                "uid": os.getuid(),
                "owner_modes": "passed",
                "atomic_replace_and_directory_sync": "passed",
                "hardlink_rejection": "passed",
                "writer_lock": "passed",
                "scope": "stdlib storage capability; no crypto, full vault or power-loss simulation",
            }
        )
    )


if __name__ == "__main__":
    main()
