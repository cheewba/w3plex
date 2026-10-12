"""Protected signing on real w3ext/defaults with an offline provider."""

import asyncio
import json
from dataclasses import replace

import pytest
from eth_account import Account as EthAccount
from eth_account._utils.legacy_transactions import Transaction
from eth_account.messages import encode_defunct, encode_typed_data
from eth_account.typed_transactions.typed_transaction import TypedTransaction
from hexbytes import HexBytes
from test_security_interaction_session import make_session, unlock
from w3ext import Chain
from web3.providers import AsyncBaseProvider

from w3plex.security.contracts import SecretKind, SecretUse
from w3plex.security.errors import PermissionDenied, SecurityError
from w3plex.security.signing import LocalSigning, SubmissionState


class OfflineProvider(AsyncBaseProvider):
    def __init__(self, *, dynamic=False, disconnect_on_send=False):
        super().__init__()
        self.calls = []
        self.raw = []
        self.dynamic = dynamic
        self.disconnect_on_send = disconnect_on_send
        self.closed = False

    async def disconnect(self):
        self.closed = True

    async def make_request(self, method, params):
        self.calls.append((method, params))
        responses = {
            "eth_chainId": "0xa",
            "eth_getTransactionCount": "0x3",
            "eth_gasPrice": "0x7",
            "eth_maxPriorityFeePerGas": "0x5",
            "eth_getBlockByNumber": {
                "number": "0x1",
                "baseFeePerGas": "0x64" if self.dynamic else "0x0",
            },
            "eth_feeHistory": {
                "oldestBlock": "0x1",
                "baseFeePerGas": ["0x64", "0x64"] if self.dynamic else ["0x0", "0x0"],
                "gasUsedRatio": [0.5],
            },
        }
        if method == "eth_sendRawTransaction":
            raw = HexBytes(params[0])
            self.raw.append(raw)
            if self.disconnect_on_send:
                raise OSError("PRIVATE credential in dependency exception")
            from web3 import Web3

            result = "0x" + Web3.keccak(raw).hex()
        else:
            assert method in responses, method
            result = responses[method]
        return {"jsonrpc": "2.0", "id": 1, "result": result}


class Approve:
    def __init__(self):
        self.requests = []
        self.allowed = True

    async def authorize(self, request):
        self.requests.append(request)
        return self.allowed


class MemoryJournal:
    # Test host only. Production hosts must provide durable encrypted storage.
    def __init__(self):
        self.records = []
        self.accept = True

    async def commit(self, record, signed_transaction):
        self.records.append((record, signed_transaction))
        return self.accept


async def setup(tmp_path, **provider_options):
    session, private, _ = make_session(tmp_path)
    await unlock(session, private)
    wallet = session._vault.add(
        SecretKind.WALLET,
        bytes.fromhex("01" * 32),
        uses=[SecretUse.TRANSACTION, SecretUse.MESSAGE, SecretUse.TYPED_MESSAGE],
    )
    provider = OfflineProvider(**provider_options)
    chain = Chain(10)
    await chain.connect_rpc(provider)
    authorizer, journal = Approve(), MemoryJournal()
    signer = LocalSigning(
        session._vault, session, authorizer=authorizer, journal=journal
    )
    return session, wallet, provider, chain, authorizer, journal, signer


@pytest.mark.parametrize("dynamic", [False, True])
def test_real_defaults_authorized_before_local_signing_and_journal_before_send(
    tmp_path, dynamic
):
    async def check():
        session, wallet, provider, chain, authorizer, journal, signer = await setup(
            tmp_path, dynamic=dynamic
        )
        original = provider.make_request

        async def require_durable_intent(method, params):
            if method == "eth_sendRawTransaction":
                assert journal.records[0][0].state is SubmissionState.PREPARED
                assert journal.records[0][1] == HexBytes(params[0])
            return await original(method, params)

        provider.make_request = require_durable_intent
        result = await signer.send(
            chain,
            wallet,
            {"to": "0x" + "22" * 20, "value": 2, "gas": 21000, "data": "0x"},
            operation="send-test",
        )
        assert result.state is SubmissionState.SUBMITTED
        intent = authorizer.requests[0]
        fields = json.loads(intent.payload)
        assert (
            fields["nonce"] == 3 and fields["chainId"] == 10 and fields["gas"] == 21000
        )
        assert fields["to"].lower() == "0x" + "22" * 20
        assert fields["value"] == 2
        if dynamic:
            assert fields["maxFeePerGas"] == 125 and fields["maxPriorityFeePerGas"] == 5
            decoded = TypedTransaction.from_bytes(provider.raw[0]).as_dict()
            assert decoded["type"] == 2
        else:
            assert fields["gasPrice"] == 7
            decoded = Transaction.from_bytes(provider.raw[0]).as_dict()
        assert decoded["nonce"] == 3
        assert EthAccount.recover_transaction(provider.raw[0]) == wallet.address
        assert bytes.fromhex("01" * 32) not in provider.raw[0]
        assert "01" * 32 not in repr(authorizer.requests)
        assert [item[0].state for item in journal.records] == [
            SubmissionState.PREPARED,
            SubmissionState.SUBMITTED,
        ]
        await session.close()

    asyncio.run(check())


@pytest.mark.parametrize(
    "field,value",
    [
        ("nonce", 9),
        ("gasPrice", 9),
        ("gas", 30000),
        ("value", 5),
        ("to", "0x" + "33" * 20),
        ("data", "0x1234"),
    ],
)
def test_changed_final_fields_and_permit_replay_are_rejected(tmp_path, field, value):
    async def check():
        session, wallet, provider, chain, _authorizer, _journal, signer = await setup(
            tmp_path
        )
        intent = await signer.prepare_transaction(
            chain, wallet, {"to": "0x" + "22" * 20, "gas": 21000}, operation="operation"
        )
        permit = await signer.authorize(intent)
        changed = json.loads(intent.payload)
        changed[field] = value
        with pytest.raises(PermissionDenied):
            signer.sign_transaction(
                replace(intent, payload=json.dumps(changed)), permit
            )
        with pytest.raises(PermissionDenied):
            signer.sign_transaction(intent, permit)
        assert provider.raw == []
        valid = await signer.authorize(intent)
        signed = signer.sign_transaction(intent, valid)
        with pytest.raises(PermissionDenied):
            signer.sign_transaction(intent, valid)
        await signer.submit(chain, signed)
        with pytest.raises(PermissionDenied):
            await signer.submit(chain, signed)
        await session.close()

    asyncio.run(check())


def test_personal_and_eip712_recovery_exact_binding_and_no_raw_key(tmp_path):
    async def check():
        session, wallet, provider, chain, _authorizer, _journal, signer = await setup(
            tmp_path
        )
        message = b"Public synthetic message"
        intent = signer.prepare_message(wallet, message, operation="personal")
        result = signer.sign_message(intent, await signer.authorize(intent))
        assert (
            EthAccount.recover_message(
                encode_defunct(message), signature=result.signature
            )
            == wallet.address
        )
        typed = {
            "types": {
                "EIP712Domain": [{"name": "chainId", "type": "uint256"}],
                "Note": [
                    {"name": "text", "type": "string"},
                    {"name": "accepted", "type": "bool"},
                ],
            },
            "primaryType": "Note",
            "domain": {"chainId": 10},
            "message": {"text": "test", "accepted": True},
        }
        intent = signer.prepare_message(wallet, typed, operation="typed")
        result = signer.sign_message(intent, await signer.authorize(intent))
        assert (
            EthAccount.recover_message(
                encode_typed_data(full_message=typed), signature=result.signature
            )
            == wallet.address
        )
        assert not hasattr(wallet, "key") and not hasattr(wallet, "_acc")
        assert not hasattr(signer, "get_secret") and not hasattr(
            signer, "register_backend"
        )
        intent = signer.prepare_message(wallet, typed, operation="typed-change")
        permit = await signer.authorize(intent)
        typed["domain"]["chainId"] = 1
        with pytest.raises(PermissionDenied):
            signer.sign_message(replace(intent, payload=json.dumps(typed)), permit)
        assert provider.raw == []
        await session.close()
        await chain.close()

    asyncio.run(check())


def test_plan_missing_authorizer_denial_lock_and_failed_journal_prevent_sending(
    tmp_path,
):
    async def check():
        session, wallet, provider, chain, authorizer, journal, signer = await setup(
            tmp_path
        )
        intent = await signer.prepare_transaction(
            chain, wallet, {"gas": 21000, "to": "0x" + "22" * 20}, operation="operation"
        )
        for options in [{"plan": True, "authorizer": authorizer}, {"authorizer": None}]:
            guarded = LocalSigning(session._vault, session, journal=journal, **options)
            with pytest.raises(PermissionDenied):
                await guarded.authorize(intent)
        authorizer.allowed = False
        with pytest.raises(PermissionDenied):
            await signer.authorize(intent)
        authorizer.allowed = True
        signed = signer.sign_transaction(intent, await signer.authorize(intent))
        journal.accept = False
        with pytest.raises(SecurityError):
            await signer.submit(chain, signed)
        assert provider.raw == []
        permit = await signer.authorize(intent)
        await session.lock()
        with pytest.raises(PermissionDenied):
            signer.sign_transaction(intent, permit)
        assert provider.raw == []
        await session.close()
        await chain.close()

    asyncio.run(check())


def test_unknown_send_result_keeps_exact_hash_and_safe_error(tmp_path):
    async def check():
        session, wallet, provider, chain, authorizer, journal, signer = await setup(
            tmp_path, disconnect_on_send=True
        )
        result = await signer.send(
            chain, wallet, {"gas": 21000, "to": "0x" + "22" * 20}, operation="uncertain"
        )
        assert result.state is SubmissionState.UNCERTAIN
        assert len(provider.raw) == 1 and len(authorizer.requests) == 1
        assert journal.records[0][0].transaction_hash == result.transaction_hash
        assert journal.records[-1][0].state is SubmissionState.UNCERTAIN
        assert "PRIVATE" not in repr(result)
        await session.close()

    asyncio.run(check())
