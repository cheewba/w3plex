"""Local software signing with final-input permits and journal-before-send."""

import asyncio
import base64
import hashlib
import json
import secrets
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated, Any, Protocol, cast

from eth_account import Account as EthAccount
from eth_account.messages import encode_defunct, encode_typed_data
from hexbytes import HexBytes
from w3ext import Chain
from w3ext.utils.common import fill_chain_id, fill_gas_price, fill_nonce
from web3 import Web3
from web3._utils.async_transactions import async_fill_transaction_defaults
from web3.middleware.signing import format_transaction
from web3.types import TxParams

from ..security.contracts import (
    Public,
    Read,
    Secret,
    SecretKind,
    SecretRef,
    SecretUse,
    WalletInfo,
)
from ..security.diagnostics import private_async
from ..security.errors import PermissionDenied, SecurityError
from ..security.session import Session, SessionState
from ..security.vault import Vault, private_call
from ..security.vault_format import canonical


class SigningKind(StrEnum):
    TRANSACTION = "transaction"
    PERSONAL = "personal"
    TYPED = "typed"


@dataclass(frozen=True)
class SigningIntent:
    operation: Annotated[str, Public]
    generation: Annotated[str, Public]
    wallet: Annotated[SecretRef, Public]
    kind: Annotated[SigningKind, Public]
    payload: Annotated[str, Public]

    @property
    def identity(self) -> str:
        value = {
            "operation": self.operation,
            "generation": self.generation,
            "wallet": self.wallet.identifier,
            "address": self.wallet.address,
            "kind": self.kind.value,
            "payload": self.payload,
        }
        return hashlib.sha256(canonical(value)).hexdigest()


class Authorizer(Protocol):
    async def authorize(self, request: Annotated[SigningIntent, Public]) -> bool: ...


@dataclass(frozen=True, repr=False)
class Permit:
    identifier: str

    def __repr__(self):
        return "Permit(<opaque>)"


@dataclass(frozen=True)
class SignatureResult:
    wallet: Annotated[SecretRef, Public]
    signature: Annotated[str, Public]
    message_hash: Annotated[str, Public]


class SubmissionState(StrEnum):
    PREPARED = "prepared"
    UNCERTAIN = "uncertain"
    SUBMITTED = "submitted"
    CONFIRMED = "confirmed"


@dataclass(frozen=True)
class Submission:
    operation: Annotated[str, Public]
    request_identity: Annotated[str, Public]
    transaction_hash: Annotated[str, Public]
    state: Annotated[SubmissionState, Public]


class Journal(Protocol):
    async def commit(
        self,
        record: Annotated[Submission, Public],
        signed_transaction: Annotated[bytes, Secret],
    ) -> bool:
        """Return True only after durable storage; signed bytes stay private."""
        ...


@dataclass(frozen=True, repr=False)
class SignedTransaction:
    intent: SigningIntent
    raw: Annotated[bytes, Secret]
    transaction_hash: str

    def __repr__(self):
        return "SignedTransaction(<private>)"


_TRANSACTION_FIELDS = {
    "from",
    "chainId",
    "nonce",
    "to",
    "value",
    "data",
    "gas",
    "gasPrice",
    "maxFeePerGas",
    "maxPriorityFeePerGas",
    "type",
    "accessList",
}


def _json_value(value):
    if isinstance(value, bytes):
        return "0x" + value.hex()
    if value is None or type(value) in {int, str, bool}:
        return value
    if isinstance(value, Mapping):
        if not all(isinstance(key, str) for key in value):
            raise PermissionDenied()
        return {key: _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    raise PermissionDenied()


class LocalSigning:
    """Trusted service adapter. Public consumers receive DTOs, never this object.

    No signing backend registration exists. All signing uses eth-account locally.
    """

    def __init__(
        self,
        vault: Vault,
        session: Session,
        *,
        authorizer: Authorizer | None,
        journal: Journal | None,
        plan: bool = False,
        permit_seconds: float = 120,
        clock=time.monotonic,
    ):
        if type(plan) is not bool or not 0 < permit_seconds <= 600:
            raise ValueError("Invalid signing policy")
        self._vault, self._session = vault, session
        self._authorizer, self._journal = authorizer, journal
        self._plan, self._permit_seconds, self._clock = plan, permit_seconds, clock
        self._permits: dict[str, tuple[str, float]] = {}
        self._signed: dict[str, SignedTransaction] = {}
        self._mutex = threading.Lock()

    def __repr__(self):
        return "LocalSigning(<private>)"

    async def _lock_resources(self) -> None:
        with self._mutex:
            self._permits.clear()
            self._signed.clear()

    def wallets(
        self, *, operation: str
    ) -> Annotated[tuple[WalletInfo, ...], Public, Read]:
        if not operation:
            raise PermissionDenied()
        status = self._session.status()
        self._session.check(status.generation)
        # Public metadata polling is not qualifying secret-use activity.
        return self._vault.wallets()

    def _current(self, intent: SigningIntent):
        status = self._session.status()
        if (
            self._plan
            or status.state is not SessionState.UNLOCKED
            or status.generation != intent.generation
            or intent.wallet.kind is not SecretKind.WALLET
            or intent.wallet.address is None
        ):
            raise PermissionDenied()

    @private_async
    async def prepare_transaction(
        self,
        chain: Chain,
        wallet: SecretRef,
        transaction: Mapping[str, Any],
        *,
        operation: str,
    ) -> SigningIntent:
        if (
            wallet.kind is not SecretKind.WALLET
            or wallet.address is None
            or not operation
            or not set(transaction) <= _TRANSACTION_FIELDS
            or any(type(value) is bool for value in transaction.values())
        ):
            raise PermissionDenied()
        status = self._session.status()
        tx = cast(TxParams, _json_value(transaction))
        supplied_sender = tx.get("from")
        if (
            supplied_sender is not None
            and Web3.to_checksum_address(supplied_sender) != wallet.address
        ):
            raise PermissionDenied()
        tx["from"] = cast(Any, wallet.address)
        tx = await fill_chain_id(chain, tx)
        if tx.get("chainId") != int(chain.chain_id):
            raise PermissionDenied()
        tx = await fill_nonce(chain, tx)
        # Chain caches fee-model detection across its task-specific RPC routes.
        tx = await fill_gas_price(chain._web3, tx)
        tx = await async_fill_transaction_defaults(chain._web3, tx)
        quantities = dict(format_transaction(tx))
        # Formatters may return hex quantities. Approval UI gets exact integers;
        # eth-account signs those same immutable normalized quantities.
        for field in (
            "chainId",
            "nonce",
            "gas",
            "value",
            "gasPrice",
            "maxFeePerGas",
            "maxPriorityFeePerGas",
            "type",
        ):
            if field in quantities:
                value = quantities[field]
                if not isinstance(value, (str, int)) or isinstance(value, bool):
                    raise PermissionDenied()
                quantities[field] = (
                    int(value, 16)
                    if isinstance(value, str) and value.startswith("0x")
                    else int(value)
                )
        material = private_call(
            lambda: canonical(_json_value(quantities)).decode("ascii")
        )
        intent = SigningIntent(
            operation, status.generation, wallet, SigningKind.TRANSACTION, material
        )
        if self._session.status().generation != status.generation:
            raise PermissionDenied()
        return intent

    def prepare_message(
        self, wallet: SecretRef, message: str | bytes | Mapping, *, operation: str
    ) -> SigningIntent:
        if not operation or wallet.kind is not SecretKind.WALLET:
            raise PermissionDenied()
        status = self._session.status()
        if isinstance(message, Mapping):
            kind = SigningKind.TYPED
            material = canonical(_json_value(message)).decode("ascii")
            private_call(lambda: encode_typed_data(full_message=json.loads(material)))
        elif isinstance(message, (str, bytes)):
            kind = SigningKind.PERSONAL
            # The convention is explicit: text means UTF-8, bytes are literal.
            # Unlike the legacy API, JSON strings are not silently typed data.
            raw = (
                private_call(lambda: message.encode("utf-8"))
                if isinstance(message, str)
                else message
            )
            material = canonical(
                {
                    "encoding": "utf8" if isinstance(message, str) else "bytes",
                    "data": base64.b64encode(raw).decode("ascii"),
                }
            ).decode("ascii")
        else:
            raise PermissionDenied()
        if len(material) > 1024 * 1024:
            raise PermissionDenied()
        return SigningIntent(operation, status.generation, wallet, kind, material)

    @private_async
    async def authorize(self, intent: SigningIntent) -> Permit:
        self._current(intent)
        if self._authorizer is None:
            raise PermissionDenied()
        task = asyncio.current_task()
        if task is None:
            raise PermissionDenied()
        self._session.track(intent.generation, task, close=self._lock_resources)
        approved = False
        try:
            approved = await self._authorizer.authorize(intent)
        except Exception:  # noqa: BLE001, S110 -- private policy errors are not logged
            pass
        if approved is not True:
            raise PermissionDenied()
        self._current(intent)
        with self._mutex:
            now = self._clock()
            self._permits = {
                key: value for key, value in self._permits.items() if value[1] > now
            }
            if len(self._permits) >= 1024:
                raise PermissionDenied()
            token = secrets.token_hex(32)
            self._permits[token] = (intent.identity, now + self._permit_seconds)
            return Permit(token)

    def _consume(self, intent: SigningIntent, permit: Permit):
        self._current(intent)
        with self._mutex:
            admitted = self._permits.pop(permit.identifier, None)
            if (
                admitted is None
                or admitted[0] != intent.identity
                or self._clock() >= admitted[1]
            ):
                raise PermissionDenied()

    def sign_transaction(
        self, intent: SigningIntent, permit: Permit
    ) -> SignedTransaction:
        if intent.kind is not SigningKind.TRANSACTION:
            raise PermissionDenied()
        self._consume(intent, permit)

        def sign():
            tx = json.loads(intent.payload)

            def local(key):
                signed = EthAccount.sign_transaction(tx, key)
                raw = bytes(signed.raw_transaction)
                return SignedTransaction(intent, raw, "0x" + Web3.keccak(raw).hex())

            return self._vault._use_secret(intent.wallet, SecretUse.TRANSACTION, local)

        signed = self._session.use(intent.generation, intent.operation, sign)
        with self._mutex:
            if len(self._signed) >= 1024:
                raise PermissionDenied()
            self._signed[signed.transaction_hash] = signed
        return signed

    def sign_message(self, intent: SigningIntent, permit: Permit) -> SignatureResult:
        if intent.kind not in {SigningKind.PERSONAL, SigningKind.TYPED}:
            raise PermissionDenied()
        self._consume(intent, permit)

        def sign():
            material = json.loads(intent.payload)
            if intent.kind is SigningKind.TYPED:
                encoded = encode_typed_data(full_message=material)
                use = SecretUse.TYPED_MESSAGE
            else:
                encoded = encode_defunct(
                    base64.b64decode(material["data"], validate=True)
                )
                use = SecretUse.MESSAGE

            def local(key):
                signed = EthAccount.sign_message(encoded, key)
                return SignatureResult(
                    intent.wallet,
                    "0x" + signed.signature.hex(),
                    "0x" + signed.message_hash.hex(),
                )

            return self._vault._use_secret(intent.wallet, use, local)

        return self._session.use(intent.generation, intent.operation, sign)

    @private_async
    async def submit(self, chain: Chain, signed: SignedTransaction) -> Submission:
        intent = signed.intent
        self._current(intent)
        if (
            self._journal is None
            or signed.transaction_hash != "0x" + Web3.keccak(signed.raw).hex()
            or json.loads(intent.payload).get("chainId") != int(chain.chain_id)
        ):
            raise PermissionDenied()
        with self._mutex:
            if self._signed.pop(signed.transaction_hash, None) is not signed:
                raise PermissionDenied()
        current_task = asyncio.current_task()
        if current_task is None:
            raise PermissionDenied()
        self._session.track(intent.generation, current_task, close=chain.close)
        prepared = Submission(
            intent.operation,
            intent.identity,
            signed.transaction_hash,
            SubmissionState.PREPARED,
        )
        committed = False
        try:
            committed = await self._journal.commit(prepared, signed.raw)
        except Exception:  # noqa: BLE001, S110 -- private journal errors are not logged
            pass
        if committed is not True:
            raise SecurityError()
        self._session.check(intent.generation)
        sent = False
        cancelled = False
        try:
            received_hash = await chain.send_raw_transaction(signed.raw)
            sent = HexBytes(received_hash) == HexBytes(signed.transaction_hash)
        except asyncio.CancelledError:
            cancelled = True
        except Exception:  # noqa: BLE001, S110 -- raw errors can contain credentials
            pass
        result = Submission(
            intent.operation,
            intent.identity,
            signed.transaction_hash,
            SubmissionState.SUBMITTED if sent else SubmissionState.UNCERTAIN,
        )
        durable = False
        try:
            durable = await asyncio.shield(self._journal.commit(result, signed.raw))
        except Exception:  # noqa: BLE001, S110 -- pre-send journal remains the recovery record
            pass
        if cancelled:
            raise asyncio.CancelledError()
        if durable is not True:
            return Submission(
                intent.operation,
                intent.identity,
                signed.transaction_hash,
                SubmissionState.UNCERTAIN,
            )
        return result

    @private_async
    async def send(
        self,
        chain: Chain,
        wallet: SecretRef,
        transaction: Mapping[str, Any],
        *,
        operation: str,
    ) -> Submission:
        intent = await self.prepare_transaction(
            chain, wallet, transaction, operation=operation
        )
        permit = await self.authorize(intent)
        signed = self.sign_transaction(intent, permit)
        return await self.submit(chain, signed)
