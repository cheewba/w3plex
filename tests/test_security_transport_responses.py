"""Projected responses cannot echo original or derived authentication values."""

import asyncio
import base64
import hashlib
import hmac

import pytest
from test_security_transport import MARKER, Client, Response, setup

from w3plex.security.errors import SecurityError
from w3plex.security.transport import AuthPlacement, RequestSpec, ResponseType


@pytest.mark.parametrize("auth", [AuthPlacement.HEADER, AuthPlacement.HMAC_SHA256])
@pytest.mark.parametrize("encoding", ["raw", "base64", "hex"])
def test_derived_authentication_cannot_leave_in_response(
    tmp_path, auth, encoding, monkeypatch
):
    async def check():
        session, reference, _policy, http = await setup(tmp_path, monkeypatch)
        value = (
            b"Bearer " + MARKER
            if auth is AuthPlacement.HEADER
            else hmac.new(MARKER, b"{}", hashlib.sha256).hexdigest().encode()
        )
        if encoding == "base64":
            value = base64.b64encode(value)
        elif encoding == "hex":
            value = value.hex().encode()
        Client.response = Response({"result": value.decode()})
        http.register(
            "read",
            RequestSpec(
                "https://public.example",
                "/read",
                "POST",
                {"result": ResponseType.TEXT},
                secret=reference,
                auth=auth,
            ),
        )
        with pytest.raises(SecurityError) as raised:
            await http.request("read", operation="echo-auth")
        assert value.decode() not in str(raised.value)
        assert raised.value.__cause__ is None and raised.value.__context__ is None
        assert Client.instances[0].closed
        await session.close()

    asyncio.run(check())


def test_private_transport_exception_and_url_are_not_forwarded(tmp_path, monkeypatch):
    async def check():
        session, reference, _policy, http = await setup(tmp_path, monkeypatch)
        http.register(
            "read",
            RequestSpec(
                "https://public.example",
                "/{credential}",
                "GET",
                {},
                secret=reference,
                auth=AuthPlacement.PATH,
            ),
        )

        def request(client, method, url, **kwargs):
            raise OSError("private request URL " + str(url))

        monkeypatch.setattr(Client, "request", request)
        with pytest.raises(SecurityError) as raised:
            await http.request("read", operation="transport-error")
        assert str(raised.value) == "security_error"
        assert raised.value.__cause__ is None and raised.value.__context__ is None
        assert Client.instances[0].closed
        await session.close()

    asyncio.run(check())


@pytest.mark.parametrize(
    "content_type,encoding,status",
    [
        ("text/html", "identity", 200),
        ("application/json", "gzip", 200),
        ("application/json", "identity", 401),
    ],
)
def test_unknown_response_envelopes_never_return_raw_body(
    tmp_path, content_type, encoding, status, monkeypatch
):
    async def check():
        session, reference, _policy, http = await setup(tmp_path, monkeypatch)
        Client.response = Response({"result": MARKER.decode()}, status=status)
        Client.response.content_type = content_type
        Client.response.headers["Content-Encoding"] = encoding
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
        with pytest.raises(SecurityError):
            await http.request("read", operation="unknown-format")
        assert Client.instances[0].closed
        await session.close()

    asyncio.run(check())
