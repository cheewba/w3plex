"""Public DTOs and classifications. These are not RPC authentication roles."""

from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated, Protocol


class Public:
    """A field explicitly approved for the public boundary."""


class Secret:
    """A field confined to trusted private interfaces."""


class Read:
    pass


class Transaction:
    pass


class Sign:
    pass


class SecretKind(StrEnum):
    DATA = "data"
    WALLET = "wallet"
    SEED = "seed"
    PASSWORD = "password"
    API = "api"
    RPC = "rpc"
    MODEL = "model"
    LEGACY_FILE_KEY = "legacy_file_key"


class SecretUse(StrEnum):
    TRANSACTION = "transaction"
    MESSAGE = "message"
    TYPED_MESSAGE = "typed_message"
    HTTP = "http"
    RECOVERY = "recovery"
    DECRYPT = "decrypt"


@dataclass(frozen=True)
class SecretRef:
    identifier: Annotated[str, Public]
    kind: Annotated[SecretKind, Public]
    address: Annotated[str | None, Public] = None


@dataclass(frozen=True)
class SafeStatus:
    code: Annotated[str, Public]


@dataclass(frozen=True)
class WalletInfo:
    reference: Annotated[SecretRef, Public]
    allowed_operations: Annotated[tuple[SecretUse, ...], Public]


class PublicWallets(Protocol):
    def wallets(
        self, *, operation: str
    ) -> Annotated[tuple[WalletInfo, ...], Public, Read]: ...
