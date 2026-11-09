"""Existing SDK clients resolve protected fields only when building requests."""

import asyncio
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, Mock

import pytest

from w3plex.security import ISecretRef, SecretString
from w3plex.security.errors import PermissionDenied, SecurityError
from w3plex.w3 import Debank

VALUE = "PUBLIC-TEST-sdk-credential"


def test_debank_keeps_a_reference_and_builds_per_request_headers(secret_store):
    source = SecretString(secret_store.capture(VALUE.encode()))
    client = Debank(access_key=source)
    headers = []

    @asynccontextmanager
    async def request(method, url, **kwargs):
        headers.append(kwargs["headers"])
        yield Mock(json=AsyncMock(return_value=[]))

    client._api_request = request
    assert asyncio.run(client._official_request("chain/list")) == []
    assert client.access_key is source
    assert headers == [{"AccessKey": VALUE}]
    secret_store._vault.lock()
    with pytest.raises(PermissionDenied):
        asyncio.run(client._official_request("chain/list"))
    assert len(headers) == 1


@pytest.mark.parametrize("failure", ["value", "safe-code", "subclass"])
def test_independent_reference_failure_has_no_private_exception_chain(failure):
    class PrivateFailure(SecurityError):
        def __str__(self):
            return VALUE

    class BrokenRef:
        def ref(self, *, silent=False):
            assert silent is True
            if failure == "safe-code":
                error = PermissionDenied()
                error.args = (VALUE,)
                raise error
            if failure == "subclass":
                raise PrivateFailure()
            raise ValueError(VALUE)

    source = BrokenRef()
    assert isinstance(source, ISecretRef)
    client = Debank(access_key=source)
    client._api_request = Mock(side_effect=AssertionError("Request was sent"))
    operation = client._official_request("chain/list")
    with pytest.raises(SecurityError) as caught:
        asyncio.run(operation)
    assert type(caught.value) is (
        PermissionDenied if failure == "safe-code" else SecurityError
    )
    assert VALUE not in str(caught.value) and VALUE not in repr(caught.value)
    assert caught.value.__context__ is None and caught.value.__cause__ is None
    client._api_request.assert_not_called()
