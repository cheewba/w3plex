"""Protected RPC with real Web3/w3ext middleware and local signatures, offline."""

import asyncio
import json

import pytest
from eth_account import Account
from hexbytes import HexBytes
from test_security_signing import Approve, MemoryJournal
from test_security_transport import MARKER, Client, Response, setup
from w3ext import Chain, chain_providers_router
from web3 import Web3
from web3.types import RPCEndpoint

from w3plex.security.contracts import SecretKind, SecretUse
from w3plex.security.errors import PermissionDenied, SecurityError
from w3plex.security.rpc import ProtectedRPC
from w3plex.security.signing import LocalSigning, SubmissionState
from w3plex.security.transport import AuthPlacement

ADDRESS = "0x" + "11" * 20


async def setup_rpc(tmp_path, monkeypatch, *, chain_id=10, hook=None):
    session, _api_reference, policy, http = await setup(tmp_path, monkeypatch)
    reference = session._vault.add(SecretKind.RPC, MARKER, uses=[SecretUse.HTTP])
    provider = ProtectedRPC(
        http,
        registration="rpc",
        operation="rpc-operation",
        chain_id=10,
        origin="https://rpc.example",
        path="/v1/{credential}",
        credential=reference,
        auth=AuthPlacement.PATH,
    )
    requests = []
    original = Client.request

    def request(client, method, url, **kwargs):
        body = kwargs["json"]
        requests.append(body)
        responses = {
            "eth_chainId": hex(chain_id),
            "eth_blockNumber": "0x2a",
            "eth_getBalance": "0x100",
            "eth_getCode": "0x1234",
            "eth_getTransactionCount": "0x3",
            "eth_gasPrice": "0x7",
            "eth_maxPriorityFeePerGas": "0x5",
            "eth_estimateGas": "0x5208",
            "eth_call": "0x" + "0" * 63 + "1",
            "eth_getBlockByNumber": {
                "number": "0x1",
                "hash": None,
                "baseFeePerGas": "0x0",
                "ignored": MARKER.decode(),
            },
            "eth_feeHistory": {
                "oldestBlock": "0x1",
                "baseFeePerGas": ["0x0", "0x0"],
                "gasUsedRatio": [0.5],
            },
            "eth_getTransactionReceipt": None,
            "eth_getTransactionByHash": None,
        }
        rpc_method = body["method"]
        result = (
            "0x" + Web3.keccak(HexBytes(body["params"][0])).hex()
            if rpc_method == "eth_sendRawTransaction"
            else responses[rpc_method]
        )
        payload = {
            "jsonrpc": "2.0",
            "id": body["id"],
            "result": result,
            "ignored": MARKER.decode(),
        }
        if hook is not None:
            payload = hook(payload)
        Client.response = Response(payload)
        return original(client, method, url, **kwargs)

    monkeypatch.setattr(Client, "request", request)
    return session, reference, policy, http, provider, requests


def test_real_chain_read_and_local_signing_through_protected_provider(
    tmp_path, monkeypatch
):
    async def check():
        session, _reference, policy, http, provider, requests = await setup_rpc(
            tmp_path, monkeypatch
        )
        wallet = session._vault.add(
            SecretKind.WALLET, bytes.fromhex("01" * 32), uses=[SecretUse.TRANSACTION]
        )
        chain = Chain(10)
        authorizer, journal = Approve(), MemoryJournal()
        signer = LocalSigning(
            session._vault, session, authorizer=authorizer, journal=journal
        )

        class ForbiddenRouter:
            def get_chain_provider(self, *args):
                raise AssertionError(
                    "Protected RPC must not select an alternate endpoint"
                )

        with (
            chain_providers_router(ForbiddenRouter(), force=True),
            chain_providers_router(None),
        ):
            await chain.connect_rpc(provider)
            assert await chain.eth.get_balance(ADDRESS) == 256
            assert await chain.eth.get_code(ADDRESS) == HexBytes("0x1234")
            result = await signer.send(
                chain,
                wallet,
                {"to": ADDRESS, "value": 2, "gas": 21000},
                operation="send",
            )
        assert result.state is SubmissionState.SUBMITTED
        fields = json.loads(authorizer.requests[0].payload)
        assert (
            fields["nonce"] == 3 and fields["chainId"] == 10 and fields["gasPrice"] == 7
        )
        raw = next(
            body["params"][0]
            for body in requests
            if body["method"] == "eth_sendRawTransaction"
        )
        assert Account.recover_transaction(raw) == wallet.address
        assert journal.records[0][1] == HexBytes(raw)
        assert MARKER.decode() not in repr(
            (provider.__dict__, policy.requests, requests, result)
        )
        assert list(provider._request_cache.items()) == []
        assert provider.global_ccip_read_enabled is False
        assert not http._clients and all(client.closed for client in Client.instances)
        await chain.close()
        with pytest.raises(PermissionDenied):
            await provider.make_request(RPCEndpoint("eth_chainId"), [])
        await session.close()

    asyncio.run(check())


@pytest.mark.parametrize(
    "method",
    [
        "eth_sign",
        "eth_signTypedData",
        "eth_sendTransaction",
        "personal_sign",
        "personal_unlockAccount",
        "eth_accounts",
        "debug_traceTransaction",
        "admin_nodeInfo",
        "eth_subscribe",
        "web3_clientVersion",
    ],
)
def test_unregistered_rpc_methods_never_reach_authorization_or_http(
    tmp_path, monkeypatch, method
):
    async def check():
        session, _reference, policy, _http, provider, requests = await setup_rpc(
            tmp_path, monkeypatch
        )
        with pytest.raises(PermissionDenied):
            await provider.make_request(RPCEndpoint(method), [])
        assert not requests and not policy.requests and not Client.instances
        await session.close()

    asyncio.run(check())


@pytest.mark.parametrize(
    "method,params",
    [
        ("eth_chainId", ["extra"]),
        ("eth_getBalance", ["https://other.example", "latest"]),
        ("eth_getBalance", [ADDRESS, "http://other.example"]),
        ("eth_call", [{"to": ADDRESS, "privateKey": MARKER.decode()}, "latest"]),
        ("eth_call", [{"to": ADDRESS, "value": "0x00"}, "latest"]),
        ("eth_getBlockByNumber", ["latest", True]),
        ("eth_getBlockByNumber", ["latest", 0]),
        ("eth_getTransactionReceipt", ["0x00"]),
        ("eth_sendRawTransaction", ["0x"]),
        ("eth_estimateGas", [{"from": ADDRESS, "gas": True}]),
        ("eth_feeHistory", ["0x401", "latest", []]),
        ("eth_feeHistory", ["0x1", "latest", [True]]),
    ],
)
def test_rpc_parameter_rejection_precedes_credential_use(
    tmp_path, monkeypatch, method, params
):
    async def check():
        session, _reference, policy, _http, provider, requests = await setup_rpc(
            tmp_path, monkeypatch
        )
        with pytest.raises(PermissionDenied):
            await provider.make_request(RPCEndpoint(method), params)
        assert not requests and not policy.requests and not Client.instances
        await session.close()

    asyncio.run(check())


@pytest.mark.parametrize(
    "field,value",
    [
        ("id", 999),
        ("jsonrpc", "1.0"),
        ("result", MARKER.decode()),
        (
            "error",
            {"code": -1, "message": MARKER.decode(), "data": {"url": MARKER.decode()}},
        ),
    ],
)
def test_rpc_invalid_envelope_and_private_errors_are_safe(
    tmp_path, monkeypatch, field, value
):
    async def check():
        session, _reference, _policy, http, provider, _requests = await setup_rpc(
            tmp_path, monkeypatch, hook=lambda payload: payload | {field: value}
        )
        with pytest.raises(SecurityError) as error:
            await provider.make_request(RPCEndpoint("eth_chainId"), [])
        assert MARKER.decode() not in str(error.value)
        assert error.value.__cause__ is None and error.value.__context__ is None
        assert not http._clients and not session._closers
        await session.close()

    asyncio.run(check())


def test_wrong_chain_and_method_override_cannot_bypass_registration(
    tmp_path, monkeypatch
):
    async def check():
        session, _reference, _policy, http, provider, requests = await setup_rpc(
            tmp_path, monkeypatch, chain_id=1
        )
        with pytest.raises(PermissionDenied):
            await provider.make_request(RPCEndpoint("eth_chainId"), [])
        assert len(requests) == 1
        with pytest.raises(PermissionDenied):
            await http.request(
                "rpc:eth_chainId",
                operation="override",
                body={"id": 1, "params": [], "method": "eth_sign"},
            )
        with pytest.raises(PermissionDenied):
            await provider.make_batch_request([(RPCEndpoint("eth_chainId"), [])])
        assert len(requests) == 1
        await session.close()

    asyncio.run(check())


def test_nullable_rpc_lookup_and_lock_prevent_authentication_reuse(
    tmp_path, monkeypatch
):
    async def check():
        session, _reference, _policy, http, provider, requests = await setup_rpc(
            tmp_path, monkeypatch
        )
        result = await provider.make_request(
            RPCEndpoint("eth_getTransactionReceipt"), ["0x" + "aa" * 32]
        )
        assert result["result"] is None
        await session.lock()
        with pytest.raises(PermissionDenied):
            await provider.make_request(RPCEndpoint("eth_chainId"), [])
        assert len(requests) == 1 and not http._clients
        assert all(client.closed for client in Client.instances)
        await session.close()

    asyncio.run(check())
