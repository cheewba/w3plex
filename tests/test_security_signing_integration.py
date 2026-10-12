"""Real w3ext fee/default and concurrent provider-context integration."""

import asyncio
import json

import pytest
from eth_account import Account
from eth_account._utils.legacy_transactions import Transaction
from eth_account.typed_transactions.typed_transaction import TypedTransaction
from test_security_signing import OfflineProvider, setup
from w3ext import Chain, chain_providers_router

from w3plex.security.contracts import SecretKind, SecretUse
from w3plex.security.errors import PermissionDenied
from w3plex.security.signing import SubmissionState


@pytest.mark.parametrize(
    "chain_id,dynamic,fees,expected",
    [
        (56, False, {}, {"gasPrice": 7}),
        (56, False, {"gasPrice": 19}, {"gasPrice": 19}),
        (10, True, {}, {"maxFeePerGas": 125, "maxPriorityFeePerGas": 5}),
        (8453, True, {"gasPrice": 6000000}, {"gasPrice": 6000000}),
        (137, True, {"gasPrice": 19}, {"gasPrice": 19}),
        (10, True, {"type": "0x1"}, {"gasPrice": 7}),
        (10, True, {"type": 2}, {"maxFeePerGas": 125, "maxPriorityFeePerGas": 5}),
        (
            10,
            True,
            {"maxFeePerGas": 150},
            {"maxFeePerGas": 150, "maxPriorityFeePerGas": 5},
        ),
        (
            10,
            True,
            {"maxPriorityFeePerGas": 8},
            {"maxFeePerGas": 128, "maxPriorityFeePerGas": 8},
        ),
        (
            10,
            True,
            {"maxFeePerGas": 150, "maxPriorityFeePerGas": 8},
            {"maxFeePerGas": 150, "maxPriorityFeePerGas": 8},
        ),
    ],
)
def test_protected_fee_behavior_matches_legacy_chain(
    tmp_path, chain_id, dynamic, fees, expected
):
    async def check():
        session, wallet, provider, chain, authorizer, _journal, signer = await setup(
            tmp_path, chain_id=chain_id, dynamic=dynamic
        )
        result = await signer.send(
            chain,
            wallet,
            {
                "gas": 25200,
                "to": "0x" + "22" * 20,
                "value": 0,
                "data": "0x1234",
                **fees,
            },
            operation="fees",
        )
        assert result.state is SubmissionState.SUBMITTED
        fields = json.loads(authorizer.requests[0].payload)
        assert fields["chainId"] == chain_id
        assert all(fields[key] == value for key, value in expected.items())
        raw = provider.raw[0]
        decoded = (
            TypedTransaction.from_bytes(raw).as_dict()
            if raw[0] in (1, 2)
            else Transaction.from_bytes(raw).as_dict()
        )
        assert all(decoded[key] == value for key, value in expected.items())
        assert Account.recover_transaction(raw) == wallet.address
        await session.close()

    asyncio.run(check())


def test_submission_to_different_chain_is_refused_before_journal_or_rpc(tmp_path):
    async def check():
        session, wallet, provider, chain, _authorizer, journal, signer = await setup(
            tmp_path
        )
        intent = await signer.prepare_transaction(
            chain,
            wallet,
            {"gas": 21000, "to": "0x" + "22" * 20},
            operation="chain-bound",
        )
        signed = signer.sign_transaction(intent, await signer.authorize(intent))
        other = Chain(1)
        with pytest.raises(PermissionDenied):
            await signer.submit(other, signed)
        assert journal.records == [] and provider.raw == []
        assert (await signer.submit(chain, signed)).state is SubmissionState.SUBMITTED
        await session.close()
        await other.close()

    asyncio.run(check())


def test_concurrent_wallets_keep_task_router_and_defaults_separate(tmp_path):
    async def check():
        session, wallet, original, chain, authorizer, journal, signer = await setup(
            tmp_path
        )
        other = session._vault.add(
            SecretKind.WALLET, bytes.fromhex("02" * 32), uses=[SecretUse.TRANSACTION]
        )
        providers = (OfflineProvider(nonce=4), OfflineProvider(nonce=8, dynamic=True))
        reached, release = asyncio.Queue(), asyncio.Event()

        class Router:
            def __init__(self, provider):
                self.provider = provider

            def get_chain_provider(self, chain_id, request_kwargs=None):
                assert chain_id == 10
                return self.provider

        async def approve(intent):
            authorizer.requests.append(intent)
            await reached.put(intent)
            await release.wait()
            return True

        authorizer.authorize = approve

        async def send(selected, provider, operation):
            with chain_providers_router(Router(provider), force=True):
                return await signer.send(
                    chain,
                    selected,
                    {"gas": 21000, "to": "0x" + "22" * 20},
                    operation=operation,
                )

        tasks = [
            asyncio.create_task(send(wallet, providers[0], "first")),
            asyncio.create_task(send(other, providers[1], "second")),
        ]
        await asyncio.wait_for(reached.get(), timeout=5)
        await asyncio.wait_for(reached.get(), timeout=5)
        assert providers[0].raw == providers[1].raw == []
        release.set()
        results = await asyncio.gather(*tasks)
        assert all(result.state is SubmissionState.SUBMITTED for result in results)
        assert original.raw == []
        assert Account.recover_transaction(providers[0].raw[0]) == wallet.address
        assert Account.recover_transaction(providers[1].raw[0]) == other.address
        fields = {
            item.operation: json.loads(item.payload) for item in authorizer.requests
        }
        assert fields["first"]["nonce"] == 4 and fields["first"]["gasPrice"] == 7
        assert (
            fields["second"]["nonce"] == 8 and fields["second"]["maxFeePerGas"] == 125
        )
        assert len(journal.records) == 4
        await session.close()
        for provider in providers:
            await provider.disconnect()

    asyncio.run(check())
