"""Offline signature recovery and exact personal/EIP-712 authorization."""

import asyncio
import json
from dataclasses import replace

import pytest
from eth_account import Account
from eth_account.messages import encode_defunct, encode_typed_data
from test_security_signing import setup

from w3plex.security.errors import PermissionDenied, SecurityError
from w3plex.security.signing import SigningKind


def typed_message():
    return {
        "types": {
            "EIP712Domain": [
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "Note": [{"name": "amount", "type": "uint256"}],
        },
        "primaryType": "Note",
        "domain": {"chainId": 10, "verifyingContract": "0x" + "22" * 20},
        "message": {"amount": 5},
    }


@pytest.mark.parametrize("message", ["0x1234", '{"text":"test"}', "", b"\x00\xff\x01"])
def test_personal_signing_preserves_explicit_text_and_bytes(tmp_path, message):
    async def check():
        session, wallet, provider, chain, authorizer, _journal, signer = await setup(
            tmp_path
        )
        intent = signer.prepare_message(wallet, message, operation="personal")
        assert intent.kind is SigningKind.PERSONAL
        result = signer.sign_message(intent, await signer.authorize(intent))
        raw = message.encode("utf-8") if isinstance(message, str) else message
        assert (
            Account.recover_message(encode_defunct(raw), signature=result.signature)
            == wallet.address
        )
        assert authorizer.requests == [intent]
        assert set(vars(result)) == {"wallet", "signature", "message_hash"}
        assert provider.raw == []
        await session.close()
        await chain.close()

    asyncio.run(check())


@pytest.mark.parametrize("change", ["domain", "contract", "types", "values", "method"])
def test_eip712_permission_covers_domain_types_values_and_method(tmp_path, change):
    async def check():
        session, wallet, provider, chain, _authorizer, _journal, signer = await setup(
            tmp_path
        )
        typed = typed_message()
        intent = signer.prepare_message(wallet, typed, operation="typed")
        permit = await signer.authorize(intent)
        if change == "domain":
            typed["domain"]["chainId"] = 1
        elif change == "contract":
            typed["domain"]["verifyingContract"] = "0x" + "33" * 20
        elif change == "types":
            typed["types"]["Note"][0]["type"] = "uint128"
        elif change == "values":
            typed["message"]["amount"] = 6
        changed = (
            replace(intent, payload=json.dumps(typed))
            if change != "method"
            else replace(intent, kind=SigningKind.PERSONAL)
        )
        with pytest.raises(PermissionDenied):
            signer.sign_message(changed, permit)
        with pytest.raises(PermissionDenied):
            signer.sign_message(intent, permit)
        valid = typed_message()
        intent = signer.prepare_message(wallet, valid, operation="typed-new")
        result = signer.sign_message(intent, await signer.authorize(intent))
        assert (
            Account.recover_message(
                encode_typed_data(full_message=valid), signature=result.signature
            )
            == wallet.address
        )
        assert provider.raw == []
        await session.close()
        await chain.close()

    asyncio.run(check())


def test_personal_payload_change_and_wrong_method_refuse_signature(tmp_path):
    async def check():
        session, wallet, provider, chain, _authorizer, _journal, signer = await setup(
            tmp_path
        )
        original = signer.prepare_message(wallet, b"one", operation="personal-change")
        changed = signer.prepare_message(wallet, b"two", operation="personal-change")
        permit = await signer.authorize(original)
        with pytest.raises(PermissionDenied):
            signer.sign_message(changed, permit)
        permit = await signer.authorize(original)
        with pytest.raises(PermissionDenied):
            signer.sign_transaction(original, permit)
        assert provider.raw == []
        await session.close()
        await chain.close()

    asyncio.run(check())


def test_invalid_utf8_and_typed_input_return_safe_failure(tmp_path):
    async def check():
        session, wallet, _provider, chain, _authorizer, _journal, signer = await setup(
            tmp_path
        )
        for message in (
            "PUBLIC-TEST-private\ud800",
            {"unknown": "PUBLIC-TEST-private"},
        ):
            with pytest.raises(SecurityError) as raised:
                signer.prepare_message(wallet, message, operation="invalid")
            assert "PUBLIC-TEST-private" not in str(raised.value)
            assert raised.value.__cause__ is None and raised.value.__context__ is None
        await session.close()
        await chain.close()

    asyncio.run(check())
