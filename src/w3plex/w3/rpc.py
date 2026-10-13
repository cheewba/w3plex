"""Explicit Web3 provider using registered, service-owned HTTP requests."""

import asyncio
import itertools
import re
from typing import Any, cast

from web3.providers import AsyncBaseProvider
from web3.types import RPCEndpoint, RPCResponse

from ..security.contracts import SecretKind, SecretRef
from ..security.diagnostics import private_async
from ..security.errors import PermissionDenied, SecurityError
from .transport import (
    AuthPlacement,
    NullableResponse,
    ProtectedHTTP,
    RequestSpec,
    ResponseShape,
    ResponseType,
)

_TEXT = ResponseType.TEXT
_OPTIONAL_TEXT = NullableResponse(_TEXT)
_TRANSACTION = {
    key: _TEXT
    for key in (
        "hash",
        "from",
        "nonce",
        "value",
        "gas",
        "gasPrice",
        "input",
        "type",
        "chainId",
        "maxFeePerGas",
        "maxPriorityFeePerGas",
        "v",
        "r",
        "s",
    )
} | {
    key: _OPTIONAL_TEXT
    for key in ("to", "blockHash", "blockNumber", "transactionIndex")
}
_LOG = {
    key: _TEXT
    for key in (
        "address",
        "data",
        "blockHash",
        "blockNumber",
        "transactionHash",
        "transactionIndex",
        "logIndex",
    )
} | {
    "topics": (_TEXT,),
    "removed": ResponseType.BOOLEAN,
}
_RESULTS: dict[str, ResponseShape] = {
    **{
        method: _TEXT
        for method in (
            "eth_chainId",
            "eth_blockNumber",
            "eth_getBalance",
            "eth_getCode",
            "eth_getTransactionCount",
            "eth_gasPrice",
            "eth_maxPriorityFeePerGas",
            "eth_call",
            "eth_estimateGas",
            "eth_sendRawTransaction",
        )
    },
    "eth_getTransactionByHash": NullableResponse(_TRANSACTION),
    "eth_getTransactionReceipt": NullableResponse(
        {
            **{
                key: _TEXT
                for key in (
                    "transactionHash",
                    "transactionIndex",
                    "blockHash",
                    "blockNumber",
                    "from",
                    "cumulativeGasUsed",
                    "gasUsed",
                    "effectiveGasPrice",
                    "status",
                    "type",
                    "logsBloom",
                )
            },
            "to": _OPTIONAL_TEXT,
            "contractAddress": _OPTIONAL_TEXT,
            "logs": (_LOG,),
        }
    ),
    "eth_getBlockByNumber": NullableResponse(
        {
            **{
                key: _TEXT
                for key in (
                    "parentHash",
                    "baseFeePerGas",
                    "gasLimit",
                    "gasUsed",
                    "timestamp",
                )
            },
            "number": _OPTIONAL_TEXT,
            "hash": _OPTIONAL_TEXT,
            "transactions": (_TEXT,),
        }
    ),
    "eth_feeHistory": {
        "oldestBlock": _TEXT,
        "baseFeePerGas": (_TEXT,),
        "gasUsedRatio": (ResponseType.NUMBER,),
        "reward": ((_TEXT,),),
    },
}


def _hex(value: Any, *, size: int | None = None, quantity: bool = False) -> bool:
    if type(value) is not str:
        return False
    if quantity:
        return re.fullmatch(r"0x(?:0|[1-9a-fA-F][0-9a-fA-F]{0,63})", value) is not None
    return (
        re.fullmatch(r"0x(?:[a-fA-F0-9]{2})*", value) is not None
        and len(value) <= 256 * 1024
        and (size is None or len(value) == 2 + 2 * size)
    )


def _block(value: Any) -> bool:
    return type(value) is str and (
        value in {"latest", "pending", "earliest", "safe", "finalized"}
        or _hex(value, quantity=True)
    )


def _call(value: Any) -> bool:
    if (
        type(value) is not dict
        or not value
        or not set(value)
        <= {
            "from",
            "to",
            "data",
            "value",
            "gas",
            "gasPrice",
            "maxFeePerGas",
            "maxPriorityFeePerGas",
        }
    ):
        return False
    return all(
        _hex(item, size=20)
        if key in {"from", "to"}
        else _hex(item)
        if key == "data"
        else _hex(item, quantity=True)
        for key, item in value.items()
    )


def _parameters(method: str, params: Any) -> bool:
    if type(params) not in {list, tuple}:
        return False
    if method in {
        "eth_chainId",
        "eth_blockNumber",
        "eth_gasPrice",
        "eth_maxPriorityFeePerGas",
    }:
        return len(params) == 0
    if method in {"eth_getBalance", "eth_getCode", "eth_getTransactionCount"}:
        return len(params) == 2 and _hex(params[0], size=20) and _block(params[1])
    if method in {"eth_getTransactionByHash", "eth_getTransactionReceipt"}:
        return len(params) == 1 and _hex(params[0], size=32)
    if method == "eth_sendRawTransaction":
        return len(params) == 1 and _hex(params[0]) and len(params[0]) > 2
    if method == "eth_getBlockByNumber":
        return len(params) == 2 and _block(params[0]) and params[1] is False
    if method == "eth_call":
        return len(params) == 2 and _call(params[0]) and _block(params[1])
    if method == "eth_estimateGas":
        return (
            len(params) in {1, 2}
            and _call(params[0])
            and (len(params) == 1 or _block(params[1]))
        )
    if method == "eth_feeHistory":
        return (
            len(params) == 3
            and _hex(params[0], quantity=True)
            and 1 <= int(params[0], 16) <= 1024
            and _block(params[1])
            and type(params[2]) is list
            and len(params[2]) <= 100
            and all(
                type(item) in {int, float} and 0 <= item <= 100 for item in params[2]
            )
            and params[2] == sorted(params[2])
        )
    return False


class ProtectedRPC(AsyncBaseProvider):
    """Trusted service object, never exported as a model-facing provider.

    There is no endpoint fallback, request cache, account, signing method, batch,
    WebSocket or CCIP-read HTTP path. Credentials stay in ProtectedHTTP.
    Use `chain_providers_router(None)` around Chain operations to stop inherited
    routers; passing this provider explicitly does not override a forced router.
    """

    global_ccip_read_enabled = False

    def __init__(
        self,
        http: ProtectedHTTP,
        *,
        registration: str,
        operation: str,
        chain_id: int,
        origin: str,
        path: str,
        credential: SecretRef | None = None,
        auth: AuthPlacement = AuthPlacement.HEADER,
        auth_name: str = "Authorization",
        auth_prefix: str = "Bearer ",
    ):
        super().__init__(cache_allowed_requests=False)
        if (
            type(chain_id) is not int
            or not 1 <= chain_id < 2**64
            or not operation
            or (credential is not None and credential.kind is not SecretKind.RPC)
        ):
            raise PermissionDenied()
        self._http, self._operation, self._chain_id = http, operation, chain_id
        self._registration = registration
        self._counter = itertools.count(1)
        self._closed = False
        self._requests: set[asyncio.Task] = set()
        for method, shape in _RESULTS.items():
            http.register(
                f"{registration}:{method}",
                RequestSpec(
                    origin,
                    path,
                    "POST",
                    {
                        "jsonrpc": _TEXT,
                        "id": ResponseType.INTEGER,
                        "result": shape,
                        "error": {"code": ResponseType.INTEGER},
                    },
                    body_fields=("id", "params"),
                    secret=credential,
                    auth=auth,
                    auth_name=auth_name,
                    auth_prefix=auth_prefix,
                    body_constants=(("jsonrpc", "2.0"), ("method", method)),
                ),
            )

    def __repr__(self):
        return "ProtectedRPC(<private>)"

    @private_async
    async def make_request(self, method: RPCEndpoint, params: Any) -> RPCResponse:
        if self._closed or not _parameters(method, params):
            raise PermissionDenied()
        request_id = next(self._counter)
        task = asyncio.current_task()
        if task is None:
            raise PermissionDenied()
        self._requests.add(task)
        try:
            result = cast(
                RPCResponse,
                await self._http.request(
                    f"{self._registration}:{method}",
                    operation=self._operation,
                    body={"id": request_id, "params": list(params)},
                ),
            )
        finally:
            self._requests.discard(task)
        if (
            result.get("jsonrpc") != "2.0"
            or result.get("id") != request_id
            or "error" in result
            or "result" not in result
            or self._closed
        ):
            raise SecurityError()
        if method == "eth_chainId" and (
            not _hex(result["result"], quantity=True)
            or int(result["result"], 16) != self._chain_id
        ):
            raise PermissionDenied()
        return result

    @private_async
    async def make_batch_request(self, requests) -> list[RPCResponse] | RPCResponse:
        raise PermissionDenied()

    @private_async
    async def is_connected(self, show_traceback: bool = False) -> bool:
        await self.make_request(RPCEndpoint("eth_chainId"), [])
        return True

    @private_async
    async def disconnect(self) -> None:
        self._closed = True
        tasks = tuple(
            task for task in self._requests if task is not asyncio.current_task()
        )
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self._request_cache.clear()
