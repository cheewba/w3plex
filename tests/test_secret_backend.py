"""An application can reuse references with encrypted records and its own IDs."""

import threading
from contextlib import contextmanager

from w3plex.security import SecretJson, SecretStore, crypto
from w3plex.security.errors import PermissionDenied


class ApplicationBackend:
    def __init__(self):
        self.key = crypto.generate_key()
        self.records = {}
        self.session = object()
        self.mutex = threading.Lock()

    def checkpoint(self):
        return self.session

    @contextmanager
    def guard(self, checkpoint):
        if not self.mutex.acquire(blocking=False):
            raise RuntimeError("This backend does not support nested guards")
        try:
            if self.session is not checkpoint:
                raise PermissionDenied()
            yield
            if self.session is not checkpoint:
                raise PermissionDenied()
        finally:
            self.mutex.release()

    def validate_identifier(self, identifier):
        if not isinstance(identifier, str) or not identifier.startswith("record/"):
            raise PermissionDenied()

    def save(self, value):
        identifier = f"record/{len(self.records)}"
        self.records[identifier] = crypto.seal(
            value, key=self.key, context=identifier.encode()
        ).to_data()
        return identifier

    def read(self, identifier):
        return crypto.unseal(
            crypto.EncryptedBlock.from_data(self.records[identifier]),
            key=self.key,
            context=identifier.encode(),
        )


def test_custom_backend_reuses_capture_adapters_and_disclosure(tmp_path):
    backend = ApplicationBackend()
    requests = []
    store = SecretStore(
        backend, confirm=lambda request: requests.append(request) or True
    )
    path = tmp_path / "source.json"
    path.write_bytes(b'{"api_key":"PUBLIC-TEST-key"}')
    source = store.capture_file(path)
    assert source.identifier == "record/0"
    value = SecretJson[str](store.reference(source.identifier), ("api_key",))
    assert value.ref() == "PUBLIC-TEST-key"
    assert requests[0].identifier == source.identifier
    assert "PUBLIC-TEST-key" not in str(backend.records)
