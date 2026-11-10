"""DeBank credentials and connection lifetime without network requests."""

import asyncio
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock

from w3plex.modules.debank import Debank

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
        assert await client.get_session() is session
        assert MARKER not in repr(dict(session.headers))
        await client.close()
        assert session.closed
        # Closing the connection keeps the caller's credential for later use.
        assert client.access_key == MARKER
        reopened = await client.get_session()
        assert reopened is not session
        await client.close()
        assert reopened.closed

    asyncio.run(check())
