"""Local credential handles stay private inside registered consumer operations."""

import asyncio
from dataclasses import asdict

import pytest
from test_security_integrations import OUTPUT, OWNER, TOKEN, quote_response
from test_security_transport import MARKER, Client, Response, setup
from web3.types import RPCEndpoint

from w3plex.security import SecretJson, SecretStore, SecretString
from w3plex.security.contracts import SecretKind
from w3plex.security.errors import PermissionDenied
from w3plex.w3.integrations import (
    ProtectedDeBank,
    ProtectedOdos,
    TokenInput,
    TokenOutput,
)
from w3plex.w3.rpc import ProtectedRPC
from w3plex.w3.transport import RequestSpec, ResponseType


def test_debank_uses_local_credential_and_authorizer_receives_only_dto(
    tmp_path, monkeypatch
):
    async def check():
        session, _, policy, http = await setup(tmp_path, monkeypatch)
        store = SecretStore(session._vault)
        source = store.capture(b'{"api_key":"' + MARKER + b'"}')
        field = SecretJson[str](source, ("api_key",))
        credential = SecretString(store.credential(field))
        debank = ProtectedDeBank(http, credential, registration="local-debank")
        Client.response = Response([])
        assert await debank.balances("0x" + "11" * 20, operation="balances") == ()
        assert Client.instances[0].seen[0][2] == {"AccessKey": MARKER.decode()}
        public = asdict(policy.requests[0])
        assert public["secret"]["kind"] == SecretKind.API
        assert set(public["secret"]) == {"identifier", "kind", "address"}
        assert MARKER.decode() not in repr(public)
        assert Client.instances[0].closed
        await session.lock()
        with pytest.raises(PermissionDenied):
            await debank.balances("0x" + "11" * 20, operation="locked")
        await session.close()

    asyncio.run(check())


def test_rpc_authenticates_with_local_rpc_reference(tmp_path, monkeypatch):
    async def check():
        session, _, _, http = await setup(tmp_path, monkeypatch)
        store = SecretStore(session._vault)
        credential = SecretString(store.capture(MARKER, kind=SecretKind.RPC))
        provider = ProtectedRPC(
            http,
            registration="local-rpc",
            operation="rpc",
            chain_id=10,
            origin="https://rpc.example",
            path="/v1",
            credential=credential,
        )
        original = Client.request

        def request(client, method, url, **kwargs):
            body = kwargs["json"]
            Client.response = Response(
                {"jsonrpc": "2.0", "id": body["id"], "result": "0xa"}
            )
            return original(client, method, url, **kwargs)

        monkeypatch.setattr(Client, "request", request)
        result = await provider.make_request(RPCEndpoint("eth_chainId"), [])
        assert result["result"] == "0xa"
        assert (
            Client.instances[0].seen[0][2]["Authorization"]
            == "Bearer " + MARKER.decode()
        )
        await provider.disconnect()
        await session.close()

    asyncio.run(check())


def test_odos_authenticates_with_local_api_reference(tmp_path, monkeypatch):
    async def check():
        session, _, _, http = await setup(tmp_path, monkeypatch)
        store = SecretStore(session._vault)
        credential = store.capture(MARKER, kind=SecretKind.API)
        odos = ProtectedOdos(
            http, registration="local-odos", chain_id=10, credential=credential
        )
        Client.response = Response(quote_response())
        quote = await odos.quote(
            OWNER,
            (TokenInput(TOKEN, 100),),
            (TokenOutput(OUTPUT, 10000),),
            operation="quote",
        )
        assert quote.inputs == (TokenInput(TOKEN, 100),)
        assert (
            Client.instances[0].seen[0][2]["Authorization"]
            == "Bearer " + MARKER.decode()
        )
        assert Client.instances[0].closed
        await session.close()

    asyncio.run(check())


def test_local_credential_permission_denial_prevents_authentication(
    tmp_path, monkeypatch
):
    async def check():
        local = tmp_path / "http-store"
        local.mkdir(mode=0o700)
        session, _, _, http = await setup(local, monkeypatch)
        store = SecretStore(session._vault, authorize=lambda access: False)
        credential = store.capture(MARKER, kind=SecretKind.API)
        http.register(
            "local",
            RequestSpec(
                "https://public.example",
                "/read",
                "GET",
                ResponseType.TEXT,
                secret=credential,
            ),
        )
        Client.response = Response("public")
        with pytest.raises(PermissionDenied):
            await http.request("local", operation="denied")
        assert Client.instances[0].seen == []
        assert Client.instances[0].closed
        await session.close()

    asyncio.run(check())


def test_unclassified_and_wrong_vault_refs_cannot_authenticate(
    tmp_path, monkeypatch, secret_store
):
    async def check():
        local = tmp_path / "http-store"
        local.mkdir(mode=0o700)
        session, _, _, http = await setup(local, monkeypatch)
        store = SecretStore(session._vault)
        for credential in [
            store.capture(MARKER),
            secret_store.capture(MARKER, kind=SecretKind.API),
        ]:
            with pytest.raises(PermissionDenied):
                http.register(
                    "local",
                    RequestSpec(
                        "https://public.example",
                        "/read",
                        "GET",
                        ResponseType.TEXT,
                        secret=credential,
                    ),
                )
        await session.close()

    asyncio.run(check())


@pytest.mark.parametrize(
    "raw,path", [(b'{"key":null}', ("key",)), (b'{"key":1}', ("key",))]
)
def test_nonstring_credential_selection_never_sends_request(
    tmp_path, monkeypatch, raw, path
):
    async def check():
        session, _, _, http = await setup(tmp_path, monkeypatch)
        store = SecretStore(session._vault)
        reference = SecretJson(store.capture(raw, kind=SecretKind.API), path)
        http.register(
            "local",
            RequestSpec(
                "https://public.example",
                "/read",
                "GET",
                ResponseType.TEXT,
                secret=reference,
            ),
        )
        with pytest.raises(PermissionDenied):
            await http.request("local", operation="invalid")
        assert Client.instances[0].seen == []
        await session.close()

    asyncio.run(check())
