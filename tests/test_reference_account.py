"""Reference accounts interoperate with w3ext without retaining key objects."""

import asyncio
import json

import pytest
from eth_account import Account as EthAccount
from eth_account.messages import encode_defunct, encode_typed_data
from eth_account.signers.local import LocalAccount
from hexbytes import HexBytes
from w3ext import Account as LegacyAccount

from w3plex.security import SecretString
from w3plex.security.errors import PermissionDenied
from w3plex.w3 import Account, Chain

KEY = "01" * 32
TYPED = {
    "types": {
        "EIP712Domain": [{"name": "chainId", "type": "uint256"}],
        "Note": [{"name": "text", "type": "string"}],
    },
    "primaryType": "Note",
    "domain": {"chainId": 1},
    "message": {"text": "public test"},
}


@pytest.mark.parametrize(
    "data,encoded",
    [
        ("hello", encode_defunct(text="hello")),
        (b"hello", encode_defunct(b"hello")),
        ("0x68656c6c6f", encode_defunct(hexstr="0x68656c6c6f")),
        (TYPED, encode_typed_data(full_message=TYPED)),
        (json.dumps(TYPED), encode_typed_data(full_message=TYPED)),
        (json.dumps(TYPED).encode(), encode_typed_data(full_message=TYPED)),
    ],
)
def test_reference_signatures_match_legacy_without_disclosure(
    secret_store, data, encoded
):
    reference = SecretString(secret_store.capture(KEY.encode()))
    account = Account.from_key(reference)
    assert account.key is reference
    assert isinstance(account, LegacyAccount)
    assert not any(isinstance(value, LocalAccount) for value in vars(account).values())
    assert KEY not in repr(vars(account))
    full = asyncio.run(account.sign(data, hex_only=False))
    assert (
        EthAccount.recover_message(encoded, signature=full.signature) == account.address
    )
    assert asyncio.run(account.sign(data)) == full.signature
    assert full.signature == asyncio.run(LegacyAccount.from_key(KEY).sign(data))
    assert str(account) == account.address
    with pytest.raises(AttributeError):
        _ = account._acc
    secret_store._vault.lock()
    with pytest.raises(PermissionDenied):
        asyncio.run(account.sign(data))


def test_reference_transaction_and_chain_binding(secret_store):
    account = Account.from_key(secret_store.capture(bytes.fromhex(KEY)))
    transaction = {
        "chainId": 1,
        "nonce": 2,
        "gasPrice": 7,
        "gas": 21000,
        "to": "0x" + "22" * 20,
        "value": 3,
    }
    signed = account.sign_transaction(transaction)
    assert EthAccount.recover_transaction(signed.raw_transaction) == account.address
    chain = Chain(1, "ETH")
    bound = account.use_chain(chain)
    assert bound.key is account.key
    assert bound.address == account.address
    with account.onchain(chain):
        assert chain._get_active_accounts()[account.address] is account
    assert chain._get_active_accounts() == {}


def test_string_construction_and_legacy_key_api_stay_compatible():
    account = Account.from_key(KEY)
    assert account.address == LegacyAccount.from_key(KEY).address
    assert account.key == HexBytes(KEY)
    assert asyncio.run(account.sign("hello")) == asyncio.run(
        LegacyAccount.from_key(KEY).sign("hello")
    )


def test_reference_account_works_after_reunlock(secret_store):
    reference = SecretString(secret_store.capture(KEY.encode()))
    account = Account.from_key(reference)
    before = asyncio.run(account.sign("hello"))
    secret_store._vault.lock()
    secret_store._vault.unlock(b"PUBLIC-TEST-snapshot-password")
    assert asyncio.run(account.sign("hello")) == before
