"""Characterize legacy credential ownership; no sockets or real credentials."""

import asyncio
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock

from w3ext.chain.providers import HTTPProviderPool

from w3plex.modules.debank import Debank
from w3plex.modules.odos import Odos

MARKER = "PUBLIC-TEST-credential-trace"


def test_legacy_debank_keeps_key_after_close_and_injects_per_request(monkeypatch):
    async def check():
        client = Debank(access_key=MARKER)
        seen = []

        @asynccontextmanager
        async def request(method, url, **kwargs):
            seen.append((method, url, kwargs))
            response = AsyncMock()
            response.json.return_value = []
            yield response

        monkeypatch.setattr(client, "_api_request", request)
        assert await client.get_nft("0x" + "11" * 20) == []
        assert seen[0][2]["headers"] == {"AccessKey": MARKER}
        session = await client.get_session()
        assert MARKER not in repr(dict(session.headers))
        await client.close()
        assert session.closed and client._session is None
        # Close owns the connection, not the legacy caller's credential field.
        assert client.access_key == MARKER

    asyncio.run(check())


def test_legacy_rpc_options_urls_and_pool_keys_retain_credentials():
    async def check():
        pool = HTTPProviderPool()
        endpoint = f"https://rpc.example/v1/{MARKER}"
        options = {"headers": {"Authorization": f"Bearer {MARKER}"}}
        provider = pool.get_provider(1, endpoint, options)
        assert MARKER in repr(pool._providers)
        assert provider.endpoint_uri == endpoint
        assert provider._request_kwargs is not options
        assert MARKER in repr(provider._request_kwargs)
        retries = provider.exception_retry_configuration
        assert retries is not None and retries.retries > 1
        await pool.close()
        assert not pool._providers
        # A retained provider still owns its copied options after disconnection.
        assert MARKER in repr(provider._request_kwargs)
        assert MARKER in str(provider)

    asyncio.run(check())


def test_legacy_odos_session_has_no_wallet_key_authentication():
    async def check():
        client = Odos(object(), object())
        session = await client.get_session()
        assert dict(session.headers) == {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        assert not hasattr(client, "access_key")
        await client.close()
        assert session.closed and client._session is None

    asyncio.run(check())
