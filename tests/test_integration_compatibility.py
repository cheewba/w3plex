"""DeBank session ownership, offline."""

import asyncio

from w3plex.modules.debank import Debank


def test_debank_session_reuse_cleanup_and_key_location():
    async def check():
        client = Debank(access_key="PUBLIC-TEST-access-key")
        assert client.access_key == "PUBLIC-TEST-access-key"
        first = await client.get_session()
        assert await client.get_session() is first
        # Legacy authentication is injected per request, not session defaults.
        assert "AccessKey" not in first.headers
        await client.close()
        assert first.closed
        assert client._session is None
        second = await client.get_session()
        assert second is not first
        await client.close()
        assert second.closed

    asyncio.run(check())
