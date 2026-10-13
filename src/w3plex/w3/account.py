"""w3ext account compatibility with opt-in, short-lived reference signing."""

import json
from collections.abc import Callable, Mapping, Sequence
from typing import Any, Self, cast

from eth_account import Account as EthAccount
from eth_account.datastructures import SignedMessage, SignedTransaction
from eth_account.messages import SignableMessage, encode_defunct, encode_typed_data
from eth_account.signers.local import LocalAccount
from hexbytes import HexBytes
from w3ext import Account as LegacyAccount

from ..security import ISecretRef
from ..security.errors import InvalidStore
from ..security.refs import safe_call


def _key(value: Any) -> bytes | str:
    if isinstance(value, bytes) and len(value) == 32:
        return value
    if isinstance(value, bytes):
        value = value.decode("ascii")
    if not isinstance(value, str):
        raise InvalidStore()
    return value if value.startswith("0x") else "0x" + value


def _message(data: bytes | str | Mapping) -> SignableMessage:
    typed = dict(data) if isinstance(data, Mapping) else None
    if typed is None and isinstance(data, (str, bytes)):
        try:
            decoded = json.loads(data)
            if isinstance(decoded, dict) and all(
                name in decoded
                for name in ("types", "primaryType", "domain", "message")
            ):
                typed = decoded
        except (TypeError, ValueError):
            pass
    if typed is not None:
        return encode_typed_data(full_message=typed)
    if isinstance(data, bytes):
        return encode_defunct(data)
    if isinstance(data, str) and data.startswith("0x"):
        return encode_defunct(hexstr=data)
    if isinstance(data, str):
        return encode_defunct(text=data)
    raise TypeError("Signing data must be bytes, text, or EIP-712 typed data")


class Account(LegacyAccount):
    """Retain a ISecretRef instead of a LocalAccount for protected keys.

    Ordinary string construction retains w3ext behavior. These are trusted local
    objects, not agent proxies; Cryptopal must authorize final signing inputs.
    """

    def __init__(self):
        self._reference: ISecretRef | None = None
        super().__init__()

    @classmethod
    def from_key(cls, key: str | ISecretRef) -> Self:
        if not isinstance(key, ISecretRef):
            return cast(Self, super().from_key(key))
        instance = cls()
        instance._reference = key
        del instance._acc
        instance.address = safe_call(
            lambda: EthAccount.from_key(_key(key.ref(silent=True))).address
        )
        return instance

    @property
    def key(self) -> bytes | ISecretRef:
        return self._reference if self._reference is not None else self._acc.key

    def _local[T](self, function: Callable[[LocalAccount], T]) -> T:
        if self._reference is None:
            return function(self._acc)
        reference = self._reference
        return safe_call(
            lambda: function(EthAccount.from_key(_key(reference.ref(silent=True))))
        )

    def sign_message(self, message: SignableMessage) -> SignedMessage:
        return self._local(lambda account: account.sign_message(message))

    def sign_transaction(
        self,
        transaction_dict: Mapping[str, Any],
        blobs: Sequence[bytes | HexBytes] | None = None,
    ) -> SignedTransaction:
        transaction = dict(transaction_dict)
        return self._local(
            lambda account: account.sign_transaction(
                cast(Any, transaction), blobs=blobs
            )
        )

    async def sign(
        self, data: bytes | str | Mapping, hex_only=True
    ) -> SignedMessage | HexBytes:
        if self._reference is None:
            return await super().sign(data, hex_only=hex_only)
        signed = self.sign_message(_message(data))
        return signed.signature if hex_only else signed

    def __getattr__(self, name: str) -> Any:
        if self.__dict__.get("_reference") is None:
            return super().__getattr__(name)
        # Do not recreate a signing account for introspection or generic access.
        raise AttributeError(name)
