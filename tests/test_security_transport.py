"""HTTP boundary checks without host sockets; real TLS probe lives in prototypes."""

import asyncio
import base64
import hashlib
import hmac
import json
import socket
from typing import ClassVar
from unittest.mock import AsyncMock
from urllib.parse import quote

import pytest
from test_security_interaction_session import make_session, unlock

from w3plex.security.contracts import SecretKind, SecretUse
from w3plex.security.errors import PermissionDenied, SecurityError
from w3plex.security.transport import (
    AuthPlacement,
    ProtectedHTTP,
    RequestSpec,
    ResponseType,
    _PinnedConnector,
)

MARKER = b"PUBLIC-TEST-api-key-Aa/+=@"


def test_binary_hmac_key_stays_in_service(tmp_path, monkeypatch):
    async def check():
        session, _reference, _policy, http = await setup(tmp_path, monkeypatch)
        key = b"\xff\x00PUBLIC-TEST-HMAC-key"
        reference = session._vault.add(SecretKind.API, key, uses=[SecretUse.HTTP])
        Client.response = Response({"result": "public"})
        http.register(
            "binary-hmac",
            RequestSpec(
                "https://public.example",
                "/v1/read",
                "POST",
                {"result": ResponseType.TEXT},
                secret=reference,
                auth=AuthPlacement.HMAC_SHA256,
                auth_name="AccessKey",
            ),
        )
        assert await http.request("binary-hmac", operation="binary-hmac") == {
            "result": "public"
        }
        headers = Client.instances[0].seen[0][2]
        assert headers["AccessKey"] == hmac.new(key, b"{}", hashlib.sha256).hexdigest()
        assert not http._clients and not session._closers
        await session.close()

    asyncio.run(check())


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_nonfinite_response_numbers_are_rejected(tmp_path, monkeypatch, value):
    async def check():
        session, reference, _policy, http = await setup(tmp_path, monkeypatch)
        Client.response = Response({"result": value})
        http.register(
            "number",
            RequestSpec(
                "https://public.example",
                "/v1/read",
                "GET",
                {"result": ResponseType.NUMBER},
                secret=reference,
            ),
        )
        with pytest.raises(SecurityError):
            await http.request("number", operation="number")
        assert not http._clients and not session._closers
        await session.close()

    asyncio.run(check())


class Policy:
    def __init__(self):
        self.requests = []

    async def authorize(self, request):
        self.requests.append(request)
        return True


class Content:
    def __init__(self, body):
        self.body = body

    async def iter_chunked(self, size):
        yield self.body


class Response:
    def __init__(self, value, *, status=200):
        self.status = status
        self.content_type = "application/json"
        self.headers = {"AccessKey": MARKER.decode()}
        self.content = Content(json.dumps(value).encode())

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None


class Client:
    response = None
    instances: ClassVar[list] = []

    def __init__(self, **kwargs):
        assert kwargs["trust_env"] is False
        assert kwargs["auto_decompress"] is False
        assert kwargs["connector"]._ssl is True
        self.connector = kwargs["connector"]
        self.closed = False
        self.seen = []
        self.instances.append(self)

    def request(self, method, url, **kwargs):
        assert kwargs["allow_redirects"] is False
        assert "proxy" not in kwargs and "ssl" not in kwargs
        self.seen.append((method, url, dict(kwargs["headers"]), kwargs["json"]))
        return self.response

    async def close(self):
        self.closed = True
        await self.connector.close()


async def setup(tmp_path, monkeypatch):
    session, private, _ = make_session(tmp_path)
    await unlock(session, private)
    reference = session._vault.add(SecretKind.API, MARKER, uses=[SecretUse.HTTP])
    policy = Policy()
    http = ProtectedHTTP(session._vault, session, authorizer=policy)
    monkeypatch.setattr("aiohttp.ClientSession", Client)
    monkeypatch.setattr(
        http, "_resolve", AsyncMock(return_value=frozenset({"8.8.8.8"}))
    )
    Client.instances = []
    return session, reference, policy, http


@pytest.mark.parametrize(
    "auth",
    [
        AuthPlacement.HEADER,
        AuthPlacement.QUERY,
        AuthPlacement.PATH,
        AuthPlacement.HMAC_SHA256,
    ],
)
def test_registered_authentication_ref_only_public_results_and_close(
    tmp_path, monkeypatch, auth
):
    async def check():
        session, reference, policy, http = await setup(tmp_path, monkeypatch)
        Client.response = Response(
            {"result": "public", "unclassified": MARKER.decode()}
        )
        path = "/v1/{credential}" if auth is AuthPlacement.PATH else "/v1/read"
        http.register(
            "registered",
            RequestSpec(
                "https://public.example",
                path,
                "POST",
                {"result": ResponseType.TEXT},
                secret=reference,
                auth=auth,
                auth_name="AccessKey",
                auth_prefix="",
                body_fields=("address",),
            ),
        )
        result = await http.request(
            "registered", operation="operation", body={"address": "0x" + "22" * 20}
        )
        assert result == {"result": "public"}
        assert MARKER.decode() not in repr(policy.requests)
        client = Client.instances[0]
        assert client.closed and not http._clients
        assert not session._closers and not session._tasks
        _, url, headers, _body = client.seen[0]
        if auth is AuthPlacement.HEADER:
            assert headers["AccessKey"] == MARKER.decode()
        elif auth is AuthPlacement.QUERY:
            assert url.query["AccessKey"] == MARKER.decode()
        elif auth is AuthPlacement.PATH:
            assert quote(MARKER.decode(), safe="") in str(url)
        else:
            assert MARKER.decode() not in headers["AccessKey"]
            assert len(headers["AccessKey"]) == 64
        await session.close()

    asyncio.run(check())


@pytest.mark.parametrize(
    "echo",
    [
        MARKER.decode(),
        MARKER.hex(),
        MARKER.hex().upper(),
        base64.b64encode(MARKER).decode(),
        base64.urlsafe_b64encode(MARKER).decode(),
        quote(MARKER.decode(), safe=""),
    ],
)
def test_known_secret_encodings_are_not_returned(tmp_path, monkeypatch, echo):
    async def check():
        session, reference, _policy, http = await setup(tmp_path, monkeypatch)
        Client.response = Response({"result": "echo " + echo})
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
        with pytest.raises(SecurityError) as caught:
            await http.request("read", operation="read")
        assert caught.value.__context__ is None
        assert echo not in str(caught.value)
        assert Client.instances[0].closed and not http._clients
        await session.close()

    asyncio.run(check())


def test_unknown_requests_input_fields_redirects_and_revoked_session_fail(
    tmp_path, monkeypatch
):
    async def check():
        session, reference, _policy, http = await setup(tmp_path, monkeypatch)
        spec = RequestSpec(
            "https://public.example",
            "/read",
            "GET",
            {"result": ResponseType.TEXT},
            secret=reference,
        )
        http.register("read", spec)
        for operation, params in [
            ("unknown", {}),
            ("read", {"url": "https://attacker.example"}),
            ("read", {"ssl": "false"}),
            ("read", {"proxy": "attacker"}),
        ]:
            with pytest.raises(PermissionDenied):
                await http.request(operation, operation="operation", parameters=params)
        for origin in (
            "http://public.example",
            "wss://public.example",
            "https://user:password@public.example",
            "https://public.example?key=secret",
        ):
            with pytest.raises(PermissionDenied):
                http.register(origin, RequestSpec(origin, "/read", "GET", {}))
        Client.response = Response({"result": "redirect"}, status=302)
        with pytest.raises(SecurityError):
            await http.request("read", operation="read")
        assert len(Client.instances) == 1 and Client.instances[0].closed
        await session.lock()
        with pytest.raises(PermissionDenied):
            await http.request("read", operation="revoked")
        await session.close()

    asyncio.run(check())


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.1",
        "169.254.169.254",
        "192.168.1.1",
        "::1",
        "fe80::1",
        "224.0.0.1",
        "0.0.0.0",
        "::ffff:10.0.0.1",
        "64:ff9b::a00:1",
        "64:ff9b::a9fe:a9fe",
        "2002:0a00:0001::1",
    ],
)
def test_resolved_private_addresses_are_denied(tmp_path, address, monkeypatch):
    async def check():
        session, _private, _ = make_session(tmp_path)
        http = ProtectedHTTP(session._vault, session, authorizer=Policy())
        loop = asyncio.get_running_loop()
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        monkeypatch.setattr(
            loop,
            "getaddrinfo",
            AsyncMock(
                return_value=[(family, socket.SOCK_STREAM, 6, "", (address, 443))]
            ),
        )
        with pytest.raises(PermissionDenied):
            await http._resolve("public.example", 443)
        await session.close()

    asyncio.run(check())


def test_actual_peer_must_match_pinned_ip_before_http_write(monkeypatch):
    async def check():
        class Transport:
            closed = False

            def get_extra_info(self, name):
                assert name == "peername"
                return ("127.0.0.1", 443)

            def close(self):
                self.closed = True

        transport = Transport()
        monkeypatch.setattr(
            "aiohttp.TCPConnector._wrap_create_connection",
            AsyncMock(return_value=(transport, object())),
        )
        connector = _PinnedConnector("public.example", frozenset({"8.8.8.8"}))
        with pytest.raises(PermissionDenied):
            await connector._wrap_create_connection()
        assert transport.closed
        await connector.close()

    asyncio.run(check())


def test_one_private_dns_answer_blocks_entire_request_before_injection(
    tmp_path, monkeypatch
):
    async def check():
        session, reference, _policy, http = await setup(tmp_path, monkeypatch)
        monkeypatch.setattr(http, "_resolve", ProtectedHTTP._resolve.__get__(http))
        monkeypatch.setattr(
            asyncio.get_running_loop(),
            "getaddrinfo",
            AsyncMock(
                return_value=[
                    (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
                    (
                        socket.AF_INET,
                        socket.SOCK_STREAM,
                        6,
                        "",
                        ("169.254.169.254", 443),
                    ),
                ]
            ),
        )
        http.register(
            "read",
            RequestSpec("https://public.example", "/read", "GET", {}, secret=reference),
        )
        monkeypatch.setattr(
            session._vault, "_use_secret", lambda *a: pytest.fail("No credential use")
        )
        with pytest.raises(PermissionDenied):
            await http.request("read", operation="mixed-dns")
        assert Client.instances == []
        await session.close()

    asyncio.run(check())


def test_pinned_dns_allows_only_registered_host(monkeypatch):
    async def check():
        connector = _PinnedConnector("public.example", frozenset({"8.8.8.8"}))
        with pytest.raises(PermissionDenied):
            await connector._resolver.resolve("other.example", 443)
        records = await connector._resolver.resolve("public.example", 443)
        assert [item["host"] for item in records] == ["8.8.8.8"]
        await connector.close()

    asyncio.run(check())
