"""Nested credential tasks and lock races use real vault/session guards."""

import asyncio

import pytest
from test_security_transport import Client, Response, setup

from w3plex.security.errors import PermissionDenied, SecurityError
from w3plex.security.transport import RequestSpec, ResponseType


def register(http, reference):
    http.register(
        "read",
        RequestSpec(
            "https://public.example",
            "/read",
            "GET",
            {"result": ResponseType.TEXT},
            secret=reference,
        ),
    )


def test_closing_nested_http_keeps_parent_tracked_until_lock(tmp_path, monkeypatch):
    async def check():
        session, reference, _policy, http = await setup(tmp_path, monkeypatch)
        register(http, reference)
        Client.response = Response({"result": "public"})
        reached, closed = asyncio.Event(), []

        async def close_parent():
            closed.append(True)

        async def parent():
            task = asyncio.current_task()
            session.track(session.status().generation, task, close=close_parent)
            assert await http.request("read", operation="nested") == {
                "result": "public"
            }
            assert Client.instances[0].closed
            assert task in session._tasks and session._closers == {close_parent}
            reached.set()
            await asyncio.Event().wait()

        task = asyncio.create_task(parent())
        await asyncio.wait_for(reached.wait(), timeout=5)
        await session.lock()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert closed == [True] and not http._clients
        assert not session._tasks and not session._closers
        await session.close()

    asyncio.run(check())


def test_http_teardown_cancels_active_task_and_refuses_new_requests(
    tmp_path, monkeypatch
):
    async def check():
        session, reference, _policy, http = await setup(tmp_path, monkeypatch)
        register(http, reference)
        reached = asyncio.Event()

        class Content:
            async def iter_chunked(self, size):
                reached.set()
                await asyncio.Event().wait()
                yield b"{}"

        Client.response = Response({})
        Client.response.content = Content()
        task = asyncio.create_task(http.request("read", operation="teardown"))
        await asyncio.wait_for(reached.wait(), timeout=5)
        await http.close()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert (
            Client.instances[0].closed and not session._tasks and not session._closers
        )
        with pytest.raises(PermissionDenied):
            await http.request("read", operation="closed")
        assert len(Client.instances) == 1
        await session.close()

    asyncio.run(check())


@pytest.mark.parametrize("action", ["lock", "teardown"])
def test_stream_stops_when_its_own_consumer_locks_or_closes(
    tmp_path, action, monkeypatch
):
    async def check():
        session, reference, _policy, http = await setup(tmp_path, monkeypatch)
        http.register(
            "stream",
            RequestSpec(
                "https://public.example",
                "/stream",
                "POST",
                {"delta": ResponseType.TEXT},
                secret=reference,
                stream_text_path=("delta",),
            ),
        )

        class Content:
            def __aiter__(self):
                return self.lines()

            async def lines(self):
                yield b'data: {"delta":"' + b"public-prefix " * 20 + b'"}\n'
                yield b'data: {"delta":"must-not-emit-after-close"}\n'

        Client.response = Response({})
        Client.response.content_type = "text/event-stream"
        Client.response.content = Content()
        stream = http.stream("stream", operation="stream", body={})
        assert (await anext(stream)).text.startswith("public-prefix")
        if action == "lock":
            await session.lock()
        else:
            await http.close()
        with pytest.raises(SecurityError):
            await anext(stream)
        assert Client.instances[0].closed and not http._clients
        assert not session._tasks and not session._closers
        await session.close()

    asyncio.run(check())


def test_lock_closes_active_response_and_prevents_credential_reuse(
    tmp_path, monkeypatch
):
    async def check():
        session, reference, _policy, http = await setup(tmp_path, monkeypatch)
        register(http, reference)
        reached = asyncio.Event()

        class Content:
            async def iter_chunked(self, size):
                reached.set()
                await asyncio.Event().wait()
                yield b'{"result":"public"}'

        Client.response = Response({})
        Client.response.content = Content()
        task = asyncio.create_task(http.request("read", operation="active"))
        await asyncio.wait_for(reached.wait(), timeout=5)
        await session.lock()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert Client.instances[0].closed
        assert not http._clients and not session._closers and not session._tasks
        with pytest.raises(PermissionDenied):
            await http.request("read", operation="after-lock")
        assert all(client.closed for client in Client.instances)
        await session.close()

    asyncio.run(check())


def test_expiry_during_authorization_prevents_injection(tmp_path, monkeypatch):
    async def check():
        session, reference, policy, http = await setup(tmp_path, monkeypatch)
        register(http, reference)

        async def authorize(_intent):
            session._deadline = session._clock()
            return True

        monkeypatch.setattr(policy, "authorize", authorize)
        monkeypatch.setattr(
            session._vault, "_use_secret", lambda *a: pytest.fail("No secret use")
        )
        with pytest.raises(PermissionDenied):
            await http.request("read", operation="expired")
        assert all(client.closed for client in Client.instances)
        assert not http._clients
        await session.close()

    asyncio.run(check())


def test_cancelled_request_closes_pool_and_drops_session_resources(
    tmp_path, monkeypatch
):
    async def check():
        session, reference, _policy, http = await setup(tmp_path, monkeypatch)
        register(http, reference)
        reached = asyncio.Event()

        class Content:
            async def iter_chunked(self, size):
                reached.set()
                await asyncio.Event().wait()
                yield b"{}"

        Client.response = Response({})
        Client.response.content = Content()
        task = asyncio.create_task(http.request("read", operation="cancel"))
        await asyncio.wait_for(reached.wait(), timeout=5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert Client.instances[0].closed and not http._clients
        assert not session._tasks and not session._closers
        await session.close()

    asyncio.run(check())
