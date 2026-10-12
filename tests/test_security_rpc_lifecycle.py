"""Cancellation of queued and authenticated explicit RPC calls."""

import asyncio

import pytest
from test_security_rpc import setup_rpc
from test_security_transport import Client
from web3.types import RPCEndpoint


@pytest.mark.parametrize("action", ["disconnect", "lock"])
def test_queued_rpc_is_cancelled_before_authentication(tmp_path, monkeypatch, action):
    async def check():
        session, _reference, policy, http, provider, requests = await setup_rpc(
            tmp_path, monkeypatch
        )
        entered, release = asyncio.Event(), asyncio.Event()

        async def authorize(intent):
            policy.requests.append(intent)
            entered.set()
            await release.wait()
            return True

        policy.authorize = authorize
        task = asyncio.create_task(
            provider.make_request(RPCEndpoint("eth_chainId"), [])
        )
        await entered.wait()
        if action == "disconnect":
            await provider.disconnect()
            with pytest.raises(asyncio.CancelledError):
                await task
        else:
            await session.lock()
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await task
        assert not requests and not http._clients and not provider._requests
        assert all(client.closed and not client.seen for client in Client.instances)
        await session.close()

    asyncio.run(check())


@pytest.mark.parametrize("action", ["disconnect", "lock"])
def test_active_rpc_is_cancelled_and_client_closed(tmp_path, monkeypatch, action):
    async def check():
        session, _reference, _policy, http, provider, requests = await setup_rpc(
            tmp_path, monkeypatch
        )
        entered, release = asyncio.Event(), asyncio.Event()
        original = Client.request

        class WaitingContent:
            async def iter_chunked(self, size):
                entered.set()
                await release.wait()
                yield b"{}"

        def request(client, *args, **kwargs):
            response = original(client, *args, **kwargs)
            response.content = WaitingContent()
            return response

        monkeypatch.setattr(Client, "request", request)
        task = asyncio.create_task(
            provider.make_request(RPCEndpoint("eth_chainId"), [])
        )
        await entered.wait()
        if action == "disconnect":
            await provider.disconnect()
        else:
            await session.lock()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert len(requests) == 1 and not http._clients and not provider._requests
        assert all(client.closed for client in Client.instances)
        await session.close()

    asyncio.run(check())
