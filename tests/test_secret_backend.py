"""An application can reuse references with encrypted records and its own IDs."""

import threading
from contextlib import contextmanager

import pytest

from w3plex.security import SecretJson, SecretStore, crypto
from w3plex.security.errors import PermissionDenied
from w3plex.security.memory import LockedBuffer


class ApplicationBackend:
    def __init__(self, protection):
        self.key = LockedBuffer(crypto.generate_key(), protection=protection)
        self.records = {}
        self.epoch = 0
        self.mutex = threading.RLock()

    def checkpoint(self):
        with self.mutex:
            return self.epoch

    @contextmanager
    def guard(self, checkpoint):
        with self.mutex:
            if self.epoch != checkpoint:
                raise PermissionDenied()
            yield
            if self.epoch != checkpoint:
                raise PermissionDenied()

    def validate_identifier(self, identifier):
        if not isinstance(identifier, str) or not identifier.startswith("record/"):
            raise PermissionDenied()

    def save(self, value):
        identifier = f"record/{len(self.records)}"
        self.records[identifier] = crypto.seal(
            value, key=self.key.copy_bytes(), context=identifier.encode()
        ).to_data()
        return identifier

    def read(self, identifier):
        return crypto.unseal(
            crypto.EncryptedBlock.from_data(self.records[identifier]),
            key=self.key.copy_bytes(),
            context=identifier.encode(),
        )


def test_custom_backend_reuses_capture_adapters_and_disclosure(protection):
    backend = ApplicationBackend(protection)
    requests = []
    store = SecretStore(
        backend, confirm=lambda request: requests.append(request) or True
    )
    try:
        source = store.capture(b'{"api_key":"PUBLIC-TEST-key"}')
        assert source.identifier == "record/0"
        value = SecretJson[str](store.reference(source.identifier), ("api_key",))
        assert value.ref() == "PUBLIC-TEST-key"
        assert requests[0].identifier == source.identifier
        assert "PUBLIC-TEST-key" not in str(backend.records)
    finally:
        backend.key.close()


def test_custom_backend_confirmation_cannot_cross_a_session(protection):
    backend = ApplicationBackend(protection)

    def confirm(request):
        backend.epoch += 1
        return True

    store = SecretStore(backend, confirm=confirm)
    try:
        source = store.capture(b"PUBLIC-TEST-key")
        with pytest.raises(PermissionDenied):
            source.ref()
        assert source.ref(silent=True) == b"PUBLIC-TEST-key"
    finally:
        backend.key.close()
