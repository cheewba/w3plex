"""Protected DeBank balances and Odos quote/assemble, without legacy accounts."""

import re
import secrets
from dataclasses import dataclass
from decimal import Decimal
from typing import Annotated, NotRequired, TypedDict, cast

from .contracts import Public, SecretKind, SecretRef
from .diagnostics import private_async
from .errors import PermissionDenied, SecurityError
from .transport import NullableResponse, ProtectedHTTP, RequestSpec, ResponseType

_TEXT = ResponseType.TEXT
_OPTIONAL_TEXT = NullableResponse(_TEXT)


class _BalanceResponse(TypedDict):
    id: str
    chain: str
    name: NotRequired[str | None]
    symbol: NotRequired[str | None]
    decimals: NotRequired[int | None]
    raw_amount: int
    price: int | float


class _QuoteResponse(TypedDict):
    pathId: str
    inTokens: list[str]
    inAmounts: list[str]
    outTokens: list[str]
    outAmounts: list[str]
    gasEstimate: int


_TransactionResponse = TypedDict(
    "_TransactionResponse",
    {
        "to": str,
        "from": NotRequired[str],
        "data": str,
        "value": str,
        "gas": int,
        "chainId": NotRequired[int],
    },
)


class _AssembleResponse(TypedDict):
    transaction: _TransactionResponse


def _address(value: str) -> str:
    if type(value) is not str or re.fullmatch(r"0x[a-fA-F0-9]{40}", value) is None:
        raise PermissionDenied()
    return value.lower()


def _amount(value: int) -> int:
    if type(value) is not int or not 0 <= value < 2**256:
        raise PermissionDenied()
    return value


def _decimal_amount(value: str) -> int:
    if type(value) is not str or re.fullmatch(r"0|[1-9][0-9]{0,77}", value) is None:
        raise SecurityError()
    return _amount(int(value))


@dataclass(frozen=True)
class TokenBalance:
    chain: Annotated[str, Public]
    token: Annotated[str, Public]
    name: Annotated[str | None, Public]
    symbol: Annotated[str | None, Public]
    decimals: Annotated[int | None, Public]
    raw_amount: Annotated[int, Public]
    usd_price: Annotated[str, Public]


class ProtectedDeBank:
    def __init__(
        self,
        http: ProtectedHTTP,
        credential: SecretRef,
        *,
        registration: str,
        origin: str = "https://pro-openapi.debank.com",
    ):
        if credential.kind is not SecretKind.API:
            raise PermissionDenied()
        self._http, self._registration = http, registration
        http.register(
            registration,
            RequestSpec(
                origin,
                "/v1/user/all_token_list",
                "GET",
                (
                    {
                        "id": _TEXT,
                        "chain": _TEXT,
                        "name": _OPTIONAL_TEXT,
                        "symbol": _OPTIONAL_TEXT,
                        "decimals": NullableResponse(ResponseType.INTEGER),
                        "raw_amount": ResponseType.INTEGER,
                        "price": ResponseType.NUMBER,
                    },
                ),
                parameters=("id", "is_all"),
                secret=credential,
                auth_name="AccessKey",
                auth_prefix="",
            ),
        )

    def __repr__(self):
        return "ProtectedDeBank(<private>)"

    @private_async
    async def balances(
        self, address: str, *, operation: str
    ) -> tuple[TokenBalance, ...]:
        records = cast(
            list[_BalanceResponse],
            await self._http.request(
                self._registration,
                operation=operation,
                parameters={"id": _address(address), "is_all": "true"},
            ),
        )
        output = []
        for record in records:
            decimals = record.get("decimals")
            price = Decimal(str(record["price"]))
            if (
                (decimals is not None and not 0 <= decimals <= 255)
                or price < 0
                or not record["chain"]
                or not record["id"]
            ):
                raise SecurityError()
            output.append(
                TokenBalance(
                    record["chain"],
                    record["id"],
                    record.get("name"),
                    record.get("symbol"),
                    decimals,
                    _amount(record["raw_amount"]),
                    format(price, "f"),
                )
            )
        return tuple(output)


@dataclass(frozen=True)
class TokenInput:
    token: Annotated[str, Public]
    amount: Annotated[int, Public]


@dataclass(frozen=True)
class TokenOutput:
    token: Annotated[str, Public]
    proportion_bps: Annotated[int, Public]


@dataclass(frozen=True)
class SwapQuote:
    identifier: Annotated[str, Public]
    chain_id: Annotated[int, Public]
    owner: Annotated[str, Public]
    inputs: Annotated[tuple[TokenInput, ...], Public]
    outputs: Annotated[tuple[TokenOutput, ...], Public]
    output_amounts: Annotated[tuple[int, ...], Public]
    slippage_bps: Annotated[int, Public]
    path_id: Annotated[str, Public]
    gas_estimate: Annotated[int, Public]


@dataclass(frozen=True)
class SwapTransaction:
    quote: Annotated[SwapQuote, Public]
    target: Annotated[str, Public]
    data: Annotated[str, Public]
    value: Annotated[int, Public]
    gas: Annotated[int, Public]


class ProtectedOdos:
    """HTTP preparation only. No automatic approval, signing or submission.

    These v2 paths match the preserved legacy integration. The trusted host can
    register a separately approved authenticated origin; agents cannot choose it.
    Quotes retain public data only and must be issued by this instance.
    """

    def __init__(
        self,
        http: ProtectedHTTP,
        *,
        registration: str,
        chain_id: int,
        origin: str = "https://api.odos.xyz",
        credential: SecretRef | None = None,
        auth_name: str = "Authorization",
        auth_prefix: str = "Bearer ",
    ):
        if (
            type(chain_id) is not int
            or not 1 <= chain_id < 2**64
            or (credential is not None and credential.kind is not SecretKind.API)
        ):
            raise PermissionDenied()
        self._http, self._registration, self._chain_id = http, registration, chain_id
        self._quotes: dict[str, SwapQuote] = {}
        http.register(
            f"{registration}:quote",
            RequestSpec(
                origin,
                "/sor/quote/v2",
                "POST",
                {
                    "pathId": _TEXT,
                    "inTokens": (_TEXT,),
                    "inAmounts": (_TEXT,),
                    "outTokens": (_TEXT,),
                    "outAmounts": (_TEXT,),
                    "gasEstimate": ResponseType.INTEGER,
                },
                body_fields=(
                    "chainId",
                    "inputTokens",
                    "outputTokens",
                    "slippageLimitPercent",
                    "userAddr",
                    "compact",
                ),
                secret=credential,
                auth_name=auth_name,
                auth_prefix=auth_prefix,
            ),
        )
        http.register(
            f"{registration}:assemble",
            RequestSpec(
                origin,
                "/sor/assemble",
                "POST",
                {
                    "transaction": {
                        "to": _TEXT,
                        "from": _TEXT,
                        "data": _TEXT,
                        "value": _TEXT,
                        "gas": ResponseType.INTEGER,
                        "chainId": ResponseType.INTEGER,
                    }
                },
                body_fields=("userAddr", "pathId", "simulate"),
                secret=credential,
                auth_name=auth_name,
                auth_prefix=auth_prefix,
            ),
        )

    def __repr__(self):
        return "ProtectedOdos(<private>)"

    @private_async
    async def quote(
        self,
        address: str,
        inputs: tuple[TokenInput, ...],
        outputs: tuple[TokenOutput, ...],
        *,
        operation: str,
        slippage_bps: int = 50,
    ) -> SwapQuote:
        if (
            type(inputs) is not tuple
            or type(outputs) is not tuple
            or not 1 <= len(inputs) <= 32
            or not 1 <= len(outputs) <= 32
            or type(slippage_bps) is not int
            or not 0 <= slippage_bps <= 10000
            or any(type(item) is not TokenInput for item in inputs)
            or any(type(item) is not TokenOutput for item in outputs)
            or len(self._quotes) >= 128
        ):
            raise PermissionDenied()
        owner = _address(address)
        normalized_inputs = tuple(
            TokenInput(_address(item.token), _amount(item.amount)) for item in inputs
        )
        normalized_outputs = tuple(
            TokenOutput(_address(item.token), item.proportion_bps) for item in outputs
        )
        if (
            any(item.amount == 0 for item in normalized_inputs)
            or any(
                type(item.proportion_bps) is not int
                or not 1 <= item.proportion_bps <= 10000
                for item in normalized_outputs
            )
            or sum(item.proportion_bps for item in normalized_outputs) != 10000
            or len({item.token for item in normalized_inputs}) != len(inputs)
            or len({item.token for item in normalized_outputs}) != len(outputs)
        ):
            raise PermissionDenied()
        result = cast(
            _QuoteResponse,
            await self._http.request(
                f"{self._registration}:quote",
                operation=operation,
                body={
                    "chainId": self._chain_id,
                    "userAddr": owner,
                    "compact": True,
                    "slippageLimitPercent": slippage_bps / 100,
                    "inputTokens": [
                        {"tokenAddress": item.token, "amount": str(item.amount)}
                        for item in normalized_inputs
                    ],
                    "outputTokens": [
                        {
                            "tokenAddress": item.token,
                            "proportion": item.proportion_bps / 10000,
                        }
                        for item in normalized_outputs
                    ],
                },
            ),
        )
        received_inputs = dict(
            zip(
                (_address(value) for value in result["inTokens"]),
                (_decimal_amount(value) for value in result["inAmounts"]),
                strict=True,
            )
        )
        received_outputs = dict(
            zip(
                (_address(value) for value in result["outTokens"]),
                (_decimal_amount(value) for value in result["outAmounts"]),
                strict=True,
            )
        )
        if (
            not result["pathId"]
            or len(result["pathId"]) > 256
            or type(result["gasEstimate"]) is not int
            or not 0 < result["gasEstimate"] < 2**64
            or received_inputs
            != {item.token: item.amount for item in normalized_inputs}
            or len(result["inTokens"]) != len(inputs)
            or set(received_outputs) != {item.token for item in normalized_outputs}
            or len(result["outTokens"]) != len(outputs)
        ):
            raise SecurityError()
        quote = SwapQuote(
            secrets.token_hex(16),
            self._chain_id,
            owner,
            normalized_inputs,
            normalized_outputs,
            tuple(received_outputs[item.token] for item in normalized_outputs),
            slippage_bps,
            result["pathId"],
            result["gasEstimate"],
        )
        self._quotes[quote.identifier] = quote
        return quote

    @private_async
    async def assemble(self, quote: SwapQuote, *, operation: str) -> SwapTransaction:
        if type(quote) is not SwapQuote or self._quotes.get(quote.identifier) != quote:
            raise PermissionDenied()
        result = cast(
            _AssembleResponse,
            await self._http.request(
                f"{self._registration}:assemble",
                operation=operation,
                body={
                    "userAddr": quote.owner,
                    "pathId": quote.path_id,
                    "simulate": False,
                },
            ),
        )
        transaction = result["transaction"]
        data = transaction["data"]
        gas = transaction["gas"]
        if (
            ("from" in transaction and _address(transaction["from"]) != quote.owner)
            or ("chainId" in transaction and transaction["chainId"] != self._chain_id)
            or type(gas) is not int
            or not 0 < gas < 2**64
            or re.fullmatch(r"0x(?:[a-fA-F0-9]{2})*", data) is None
        ):
            raise SecurityError()
        return SwapTransaction(
            quote,
            _address(transaction["to"]),
            data,
            _decimal_amount(transaction["value"]),
            gas,
        )

    def discard_quote(self, identifier: str) -> None:
        self._quotes.pop(identifier, None)
