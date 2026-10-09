import asyncio
from unittest.mock import AsyncMock, Mock

import pytest
from w3ext import Chain, Currency, TokenAmount

from w3plex.modules.debank.debank import EstimatedCurrencyAmount, EstimatedTokenAmount
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
