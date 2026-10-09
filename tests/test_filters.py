import asyncio
from unittest.mock import AsyncMock, Mock

from w3ext import Chain, Currency

from w3plex.utils.filter import AmountFilter, ContractLookup, TokenLookup


def test_token_lookup_skips_missing_tokens():
    chain = Mock(spec=Chain)
    chain.load_token = AsyncMock(return_value=None)
    lookup = TokenLookup("*:0x0000000000000000000000000000000000000001")
    assert asyncio.run(lookup([chain])) == []


def test_token_lookup_accepts_chain_iterables():
    chain = Mock(spec=Chain)
    chain.eth = Currency("Ether", "ETH", 18)
    chains = {"ethereum": chain}
    assert asyncio.run(TokenLookup("*:eth")(chains.values())) == [(chain.eth, chain)]


def test_contract_lookup_returns_contract_and_chain_and_passes_abi():
    chain = Mock(spec=Chain)
    abi = "contract ABI"
    address = "0x0000000000000000000000000000000000000001"
    result = asyncio.run(ContractLookup(f"*:{address}", abi)([chain]))
    assert result == [(chain.contract.return_value, chain)]
    chain.contract.assert_called_once_with(address, abi=abi)


def test_amount_filter_handles_absent_chain_and_numeric_amounts():
    currency = Currency("Ether", "ETH", 18)
    assert AmountFilter("*:Ether>1")(amount=currency(2), chain=None)
    assert not AmountFilter("*:Missing>1")(amount=currency(2), chain=None)
