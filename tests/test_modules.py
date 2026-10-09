import asyncio
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, Mock

import pytest
from w3ext import Chain, Currency, TokenAmount

from w3plex.apps.balance.app import onchain_balance
from w3plex.modules.debank.debank import (
    Debank,
    EstimatedCurrencyAmount,
    EstimatedTokenAmount,
)
from w3plex.modules.module import ModuleError
from w3plex.modules.odos import Odos, TransactionFailed


def test_estimated_currency_amount_preserves_price_during_arithmetic():
    currency = Currency("Ether", "ETH", 18)
    amount = EstimatedCurrencyAmount(currency, 10**18, 2500)
    total = amount + amount
    assert total.usd_price == 5000
    assert total.price == 2500


def test_estimated_token_amount_keeps_token_behavior():
    token = Mock()
    token.decimals = 6
    token.symbol = "USDC"
    amount = EstimatedTokenAmount(token, 10**6, 1)
    assert isinstance(amount, TokenAmount)
    assert amount.usd_price == 1


def test_odos_formats_output_without_mutating_tokens():
    tokens = [Currency(f"Token {i}", f"T{i}", 18) for i in range(3)]
    original = list(tokens)
    odos = object.__new__(Odos)
    output = odos._format_output(tokens)
    assert tokens == original
    proportions = [item["proportion"] for item in output]
    assert proportions == pytest.approx([0.33, 0.33, 0.34])
    assert sum(proportions) == pytest.approx(1)


def test_odos_preserves_explicit_output_proportions():
    currency = Currency("Ether", "ETH", 18)
    odos = object.__new__(Odos)
    assert odos._format_output(currency)[0]["proportion"] == 1
    assert odos._format_output([(currency, 0.75)])[0]["proportion"] == 0.75


def test_odos_rejects_failed_receipt_mapping():
    odos = object.__new__(Odos)
    odos.chain = Mock(spec=Chain)
    odos.chain.send_transaction = AsyncMock(return_value="tx hash")
    odos.chain.wait_for_transaction_receipt = AsyncMock(return_value={"status": 0})
    odos.chain.get_tx_scan.return_value = "transaction URL"
    odos.account = Mock(address="account")
    odos._build_swap_tx = AsyncMock(return_value={"transaction": {"to": "spender"}})
    odos._check_permissions = AsyncMock(return_value=False)
    quote = Mock(input=[])
    with pytest.raises(TransactionFailed, match="Swap error: 0"):
        asyncio.run(odos.swap(quote))


def test_debank_official_api_fetches_nfts_and_projects(monkeypatch):
    client = Debank(access_key="test key")
    calls = []

    @asynccontextmanager
    async def request(method, url, **kwargs):
        calls.append((method, url, kwargs))
        yield Mock(json=AsyncMock(return_value=[{"id": "result"}]))

    monkeypatch.setattr(client, "_api_request", request)
    assert asyncio.run(client.get_nft("0xABC")) == [{"id": "result"}]
    assert asyncio.run(client.get_projects("0xABC")) == [{"id": "result"}]
    assert calls[0][1].endswith("/user/all_nft_list")
    assert calls[1][1].endswith("/user/all_complex_protocol_list")
    assert calls[0][2] == {
        "headers": {"AccessKey": "test key"},
        "params": {"id": "0xabc", "is_all": "true"},
    }
    with pytest.raises(ModuleError, match="access_key"):
        asyncio.run(Debank().get_projects("address"))


def test_debank_balance_preserves_zero_raw_amount_and_scales_human_amounts():
    client = Debank()
    chain = Chain(1, "ETH", name="ethereum")
    data = {
        "id": "eth",
        "name": "Ether",
        "symbol": "ETH",
        "decimals": 18,
        "raw_amount": 0,
        "balance": 9,
        "price": 2500,
    }
    assert asyncio.run(client._format_balance_output(data, chain)).amount == 0
    data.pop("raw_amount")
    data["balance"] = "1.25"
    assert (
        asyncio.run(client._format_balance_output(data, chain)).amount == 125 * 10**16
    )


def test_debank_official_balance_applies_chain_filters(monkeypatch):
    client = Debank(access_key="test key")
    chain = Chain(1, "ETH", name="ethereum")
    data = [
        {
            "chain": "eth",
            "id": "eth",
            "name": "Ether",
            "symbol": "ETH",
            "decimals": 18,
            "amount": 2,
            "price": 2500,
        }
    ]
    monkeypatch.setattr(client, "_official_request", AsyncMock(return_value=data))
    monkeypatch.setattr(client, "_get_chain", AsyncMock(return_value=chain))
    result = asyncio.run(client.get_balance("address", chains_filter=lambda item: True))
    assert result[chain][0].to_fixed() == 2
    assert (
        asyncio.run(client.get_balance("address", chains_filter=lambda item: False))
        == {}
    )


@pytest.mark.parametrize(
    "kwargs", [{"threads": 0}, {"threads": 1.5}, {"attempts": 0}, {"attempts": 1.5}]
)
def test_balance_rejects_limits_that_would_deadlock_or_retry_incorrectly(kwargs):
    with pytest.raises(ValueError, match="positive"):
        asyncio.run(onchain_balance("address", **kwargs))
