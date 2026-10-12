"""Real registered HTTP admission and protected API projection, without sockets."""

import asyncio
from dataclasses import replace

import pytest
from test_security_transport import MARKER, Client, Response, setup

from w3plex.security.errors import PermissionDenied, SecurityError
from w3plex.security.integrations import (
    ProtectedDeBank,
    ProtectedOdos,
    TokenInput,
    TokenOutput,
)

OWNER = "0x" + "11" * 20
TOKEN = "0x" + "22" * 20
OUTPUT = "0x" + "33" * 20
TARGET = "0x" + "44" * 20


def quote_response():
    return {
        "pathId": "public-path-id",
        "inTokens": [TOKEN],
        "inAmounts": ["100"],
        "outTokens": [OUTPUT],
        "outAmounts": ["90"],
        "gasEstimate": 200000,
        "unclassified": MARKER.decode(),
    }


async def make_odos(tmp_path, monkeypatch):
    session, reference, policy, http = await setup(tmp_path, monkeypatch)
    odos = ProtectedOdos(http, registration="odos", chain_id=10, credential=reference)
    Client.response = Response(quote_response())
    quote = await odos.quote(
        OWNER,
        (TokenInput(TOKEN, 100),),
        (TokenOutput(OUTPUT, 10000),),
        operation="quote",
    )
    return session, reference, policy, http, odos, quote


def test_debank_nullable_metadata_exact_integer_and_private_authentication(
    tmp_path, monkeypatch
):
    async def check():
        session, reference, policy, http = await setup(tmp_path, monkeypatch)
        debank = ProtectedDeBank(http, reference, registration="debank")
        Client.response = Response(
            [
                {
                    "id": TOKEN,
                    "chain": "eth",
                    "name": None,
                    "symbol": None,
                    "decimals": None,
                    "raw_amount": 2**128 + 7,
                    "price": 1.5,
                    "raw_headers": MARKER.decode(),
                }
            ]
        )
        result = await debank.balances(OWNER, operation="balances")
        assert result[0].raw_amount == 2**128 + 7
        assert result[0].name is None and result[0].decimals is None
        assert result[0].usd_price == "1.5"
        client = Client.instances[0]
        method, url, headers, body = client.seen[0]
        assert method == "GET" and url.path == "/v1/user/all_token_list"
        assert dict(url.query) == {"id": OWNER, "is_all": "true"}
        assert headers == {"AccessKey": MARKER.decode()}
        assert body is None and client.closed
        assert MARKER.decode() not in repr((result, debank, policy.requests))
        assert not http._clients and not session._closers
        await session.close()

    asyncio.run(check())


@pytest.mark.parametrize(
    "field,value",
    [
        ("raw_amount", -1),
        ("raw_amount", True),
        ("decimals", 256),
        ("price", -1),
        ("name", MARKER.decode()),
    ],
)
def test_debank_invalid_or_echoed_fields_return_only_safe_error(
    tmp_path, monkeypatch, field, value
):
    async def check():
        session, reference, _policy, http = await setup(tmp_path, monkeypatch)
        debank = ProtectedDeBank(http, reference, registration="debank")
        record = {
            "id": TOKEN,
            "chain": "eth",
            "raw_amount": 1,
            "price": 1,
            "decimals": 18,
            "name": "Test",
        }
        record[field] = value
        Client.response = Response([record])
        with pytest.raises(SecurityError) as error:
            await debank.balances(OWNER, operation="balances")
        assert MARKER.decode() not in str(error.value)
        assert error.value.__context__ is None and error.value.__cause__ is None
        assert not http._clients
        await session.close()

    asyncio.run(check())


def test_odos_quote_and_assemble_do_not_approve_sign_or_retain_keys(
    tmp_path, monkeypatch
):
    async def check():
        session, _reference, policy, _http, odos, quote = await make_odos(
            tmp_path, monkeypatch
        )
        request = Client.instances[0].seen[0][3]
        assert request["inputTokens"] == [{"tokenAddress": TOKEN, "amount": "100"}]
        assert request["outputTokens"] == [{"tokenAddress": OUTPUT, "proportion": 1.0}]
        assert request["userAddr"] == OWNER and request["chainId"] == 10
        assert request["slippageLimitPercent"] == 0.5
        Client.response = Response(
            {
                "transaction": {
                    "to": TARGET,
                    "from": OWNER,
                    "data": "0x1234",
                    "value": "0",
                    "gas": 210000,
                    "chainId": 10,
                    "ignored": MARKER.decode(),
                },
                "ignored": MARKER.decode(),
            }
        )
        transaction = await odos.assemble(quote, operation="assemble")
        assert transaction.quote == quote and transaction.target == TARGET
        assert transaction.value == 0 and transaction.data == "0x1234"
        assert Client.instances[1].seen[0][3] == {
            "userAddr": OWNER,
            "pathId": quote.path_id,
            "simulate": False,
        }
        assert len(policy.requests) == 2
        assert all(client.closed for client in Client.instances)
        assert MARKER.decode() not in repr(
            (odos.__dict__, quote, transaction, policy.requests)
        )
        odos.discard_quote(quote.identifier)
        with pytest.raises(PermissionDenied):
            await odos.assemble(quote, operation="again")
        assert len(Client.instances) == 2
        await session.close()

    asyncio.run(check())


@pytest.mark.parametrize(
    "field,value",
    [
        ("path_id", "changed-path"),
        ("chain_id", 1),
        ("owner", TARGET),
        ("slippage_bps", 100),
        ("inputs", (TokenInput(TOKEN, 101),)),
    ],
)
def test_odos_rejects_modified_or_foreign_quotes_before_http(
    tmp_path, monkeypatch, field, value
):
    async def check():
        session, _reference, policy, _http, odos, quote = await make_odos(
            tmp_path, monkeypatch
        )
        with pytest.raises(PermissionDenied):
            await odos.assemble(replace(quote, **{field: value}), operation="modified")
        assert len(Client.instances) == len(policy.requests) == 1
        await session.close()

    asyncio.run(check())


@pytest.mark.parametrize(
    "field,value",
    [
        ("chainId", 1),
        ("from", TARGET),
        ("gas", 0),
        ("value", "-1"),
        ("value", "01"),
        ("data", "0x123"),
        ("to", "https://other.example"),
    ],
)
def test_odos_rejects_mismatched_or_invalid_transaction(
    tmp_path, monkeypatch, field, value
):
    async def check():
        session, _reference, _policy, _http, odos, quote = await make_odos(
            tmp_path, monkeypatch
        )
        transaction = {
            "to": TARGET,
            "from": OWNER,
            "data": "0x1234",
            "value": "0",
            "gas": 200000,
            "chainId": 10,
        }
        transaction[field] = value
        Client.response = Response({"transaction": transaction})
        with pytest.raises(SecurityError):
            await odos.assemble(quote, operation="assemble")
        assert all(client.closed for client in Client.instances)
        await session.close()

    asyncio.run(check())


@pytest.mark.parametrize(
    "field,value",
    [
        ("inAmounts", ["101"]),
        ("inTokens", [TARGET]),
        ("outTokens", [TARGET]),
        ("outAmounts", []),
        ("pathId", MARKER.decode()),
    ],
)
def test_odos_rejects_server_quote_substitution(tmp_path, monkeypatch, field, value):
    async def check():
        session, reference, _policy, http = await setup(tmp_path, monkeypatch)
        odos = ProtectedOdos(
            http, registration="odos", chain_id=10, credential=reference
        )
        result = quote_response()
        result[field] = value
        Client.response = Response(result)
        with pytest.raises(SecurityError):
            await odos.quote(
                OWNER,
                (TokenInput(TOKEN, 100),),
                (TokenOutput(OUTPUT, 10000),),
                operation="quote",
            )
        assert not odos._quotes
        await session.close()

    asyncio.run(check())


def test_odos_reordered_response_keeps_requested_amounts_and_outputs(
    tmp_path, monkeypatch
):
    async def check():
        session, reference, _policy, http = await setup(tmp_path, monkeypatch)
        odos = ProtectedOdos(
            http, registration="odos", chain_id=10, credential=reference
        )
        second_input, second_output = "0x" + "55" * 20, "0x" + "66" * 20
        Client.response = Response(
            {
                "pathId": "public-path-id",
                "gasEstimate": 200000,
                "inTokens": [second_input, TOKEN],
                "inAmounts": ["200", "100"],
                "outTokens": [second_output, OUTPUT],
                "outAmounts": ["180", "90"],
            }
        )
        quote = await odos.quote(
            OWNER,
            (TokenInput(TOKEN, 100), TokenInput(second_input, 200)),
            (TokenOutput(OUTPUT, 5000), TokenOutput(second_output, 5000)),
            operation="quote",
        )
        assert quote.inputs == (TokenInput(TOKEN, 100), TokenInput(second_input, 200))
        assert quote.output_amounts == (90, 180)
        await session.close()

    asyncio.run(check())


def test_invalid_public_inputs_and_locked_credentials_do_not_connect(
    tmp_path, monkeypatch
):
    async def check():
        session, reference, policy, http = await setup(tmp_path, monkeypatch)
        debank = ProtectedDeBank(http, reference, registration="debank")
        with pytest.raises(PermissionDenied):
            await debank.balances("https://other.example", operation="invalid")
        assert not Client.instances and not policy.requests
        odos = ProtectedOdos(
            http, registration="odos", chain_id=10, credential=reference
        )
        with pytest.raises(PermissionDenied):
            await odos.quote(
                OWNER,
                (TokenInput(TOKEN, True),),
                (TokenOutput(OUTPUT, 10000),),
                operation="invalid",
            )
        assert not Client.instances and not policy.requests
        await session.lock()
        with pytest.raises(PermissionDenied):
            await debank.balances(OWNER, operation="locked")
        assert all(client.closed and not client.seen for client in Client.instances)
        await session.close()

    asyncio.run(check())
