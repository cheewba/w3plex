"""Real legacy Odos approval flow and DeBank session ownership, offline."""

import asyncio
from unittest.mock import AsyncMock, Mock

import pytest
from w3ext import Chain, Currency, TokenAmount

from w3plex.modules.debank import Debank
from w3plex.modules.odos import Odos


def setup_odos(allowances):
    odos = object.__new__(Odos)
    odos.account = Mock(address="0x" + "11" * 20)
    odos.chain = Mock(spec=Chain)
    odos.chain.get_nonce = AsyncMock(return_value=4)
    odos.chain.wait_for_transaction_receipt = AsyncMock(return_value={"status": 1})
    tokens = []
    for allowance in allowances:
        token = Mock()
        token.decimals = 18
        token.symbol = "TEST"
        token.get_allowance = AsyncMock(return_value=TokenAmount(token, allowance))
        token.approve = AsyncMock(return_value=f"hash-{len(tokens)}")
        tokens.append(token)
    return odos, tokens


def test_odos_checks_each_allowance_and_assigns_separate_nonces():
    odos, tokens = setup_odos([0, 10, 0])
    inputs = [TokenAmount(token, 10) for token in tokens]
    inputs.append(Currency("Ether", "ETH", 18)(1))
    spender = "0x" + "22" * 20
    assert asyncio.run(odos._check_permissions(inputs, odos.account.address, spender))
    for token in tokens:
        token.get_allowance.assert_awaited_once_with(odos.account.address, spender)
    assert tokens[0].approve.await_args.args == (
        odos.account,
        spender,
        inputs[0],
        {"nonce": 4},
    )
    tokens[1].approve.assert_not_awaited()
    assert tokens[2].approve.await_args.args == (
        odos.account,
        spender,
        inputs[2],
        {"nonce": 5},
    )
    assert {
        call.args[0] for call in odos.chain.wait_for_transaction_receipt.await_args_list
    } == {"hash-0", "hash-2"}


def test_odos_no_approval_and_permission_failure_prevent_swap():
    odos, tokens = setup_odos([10])
    assert not asyncio.run(
        odos._check_permissions(
            [TokenAmount(tokens[0], 10)], odos.account.address, "spender"
        )
    )
    odos.chain.get_nonce.assert_not_awaited()
    odos._build_swap_tx = AsyncMock(return_value={"transaction": {"to": "spender"}})
    tokens[0].get_allowance.side_effect = RuntimeError("offline allowance error")
    odos.chain.send_transaction = AsyncMock()
    with pytest.raises(RuntimeError, match="allowance"):
        asyncio.run(odos.swap(Mock(input=[TokenAmount(tokens[0], 10)])))
    odos.chain.send_transaction.assert_not_awaited()


def test_odos_approval_failure_stops_final_swap():
    odos, tokens = setup_odos([0])
    tokens[0].approve.side_effect = RuntimeError("approval refused")
    odos._build_swap_tx = AsyncMock(return_value={"transaction": {"to": "spender"}})
    odos.chain.send_transaction = AsyncMock()
    with pytest.raises(RuntimeError, match="refused"):
        asyncio.run(odos.swap(Mock(input=[TokenAmount(tokens[0], 10)])))
    odos.chain.send_transaction.assert_not_awaited()
    odos.chain.wait_for_transaction_receipt.assert_not_awaited()


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
