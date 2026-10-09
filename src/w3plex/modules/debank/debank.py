import asyncio
import itertools
from collections import defaultdict
from collections.abc import Callable
from contextlib import AsyncExitStack, asynccontextmanager
from typing import Any, ClassVar, Self, cast

import aiohttp
from aiohttp_socks import ProxyConnector as _ProxyConnector
from w3ext import Chain, Currency, CurrencyAmount, Token, TokenAmount

from ..module import ModuleError
from .constants import (
    AWAILABLE_CHAINS_API_URL,
    CACHED_BALANCE_API_URL,
    CHAIN_BALANCE_API_URL,
    PROFILE_PAGE,
    USED_CHAINS_API_URL,
    USER_AGENT,
)

DEFAULT_CURRENCY = "UNKNOWN"


class ProxyConnector(_ProxyConnector):
    @classmethod
    def from_url(cls, url: str, **kwargs: Any) -> "ProxyConnector":
        rdns = False
        if url.startswith("socks5h://"):
            rdns = True
            url = url.replace("socks5h://", "socks5://")
        return cast(ProxyConnector, super().from_url(url, rdns=rdns, **kwargs))


class _DebankExt[TC: Currency](CurrencyAmount[TC]):
    def __init__(self, currency: TC, amount: int | str, price: float) -> None:
        super().__init__(currency, amount)
        self.price = price or 0

    @property
    def usd_price(self):
        return round(self.to_fixed() * self.price, 2)

    def _new_amount(self: Self, amount: int | str) -> Self:
        return self.__class__(self.currency, amount, self.price)

    def __str__(self) -> str:
        return f"{super().__str__()} (${self.usd_price})"


class EstimatedCurrencyAmount(_DebankExt[Currency]):
    """Extended version of ``CurrencyAmount`` that also includes a price."""


class EstimatedTokenAmount(_DebankExt[Token], TokenAmount):
    """Extended version of ``TokenAmount`` that also includes a price."""


class Debank:
    name = "debank"
    _all_chains: ClassVar[dict[str, Chain] | None] = None

    def __init__(
        self,
        proxy: str | None = None,
        chains: list["Chain"] | None = None,
        threads: int | None = 1,
    ) -> None:
        self._chains = {chain.chain_id: chain for chain in chains or []}

        # setup session default args
        session_kwargs = {}
        if proxy:
            session_kwargs["connector"] = ProxyConnector.from_url(proxy)
        self._proxy = proxy
        self._session = aiohttp.ClientSession(**session_kwargs)
        self._threads = threads

    async def close(self):
        if self._session is not None:
            await self._session.close()

    @classmethod
    def account_link(cls, address: str):
        return PROFILE_PAGE.format(address=address)

    async def _format_balance_output(
        self, data: dict, chain: Chain
    ) -> EstimatedCurrencyAmount | EstimatedTokenAmount | None:
        kwargs = {key: data[key] for key in ["name", "symbol", "decimals"]}
        amount = data.get("raw_amount") or data["balance"]
        if data["id"].startswith("0x"):
            # process token
            token = await chain.load_token(data["id"], **kwargs)
            if token is None:
                return None
            return EstimatedTokenAmount(token, amount, data["price"])
        else:
            # process currency
            currency = Currency(**kwargs)
            if chain.currency.name == DEFAULT_CURRENCY:
                chain.currency = currency
            return EstimatedCurrencyAmount(currency, amount, data["price"])

    async def _get_chain(self, debank_id: str) -> "Chain":
        all_chains = getattr(self.__class__, "_all_chains", None)
        if all_chains is None:
            async with self._api_request("get", AWAILABLE_CHAINS_API_URL) as resp:
                all_chains = {
                    chain["id"]: Chain(
                        chain["network_id"],
                        chain["token_symbol"],
                        chain.get("explorer_host"),
                        chain.get("name") or chain["id"],
                    )
                    for chain in (await resp.json())["data"]["chains"]
                }
                # cache the output for all debank instances
                self.__class__._all_chains = all_chains
        debank_chain = all_chains[debank_id]

        return self._chains.get(debank_chain.chain_id) or debank_chain

    @asynccontextmanager
    async def _api_request(self, method, url, *, headers=None, **kwargs):
        headers = await self.get_request_headers(method, url, headers=headers, **kwargs)
        async with self._session.request(
            method, url, headers=headers, **kwargs
        ) as resp:
            if not resp.status == 200:
                raise ModuleError(
                    f"{self.name}: Can't retrieve {url} - `{resp.reason}`"
                )
            yield resp

    async def get_request_headers(self, method, url, headers=None, **kwargs) -> dict:
        return {
            "User-Agent": USER_AGENT,
            "Referer": "https://debank.com/",
            "Source": "web",
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-US,en;q=0.9;q=0.8",
            "Cache-Control": "no-cache",
            "Origin": "https://debank.com",
            "Pragma": "no-cache",
            **(headers or {}),
        }

    async def get_balance(
        self,
        address: str,
        *,
        cached_only: bool = False,
        chains_filter: Callable[[Chain], bool] | None = None,
    ) -> dict["Chain", list[EstimatedCurrencyAmount | EstimatedTokenAmount]]:
        address = str(address).lower()

        if cached_only:
            async with self._api_request(
                "get", CACHED_BALANCE_API_URL.format(address=address)
            ) as resp:
                data = (await resp.json())["data"]

        else:
            # Get all used chains to load balance for each of them
            async with self._api_request(
                "get", USED_CHAINS_API_URL.format(address=address)
            ) as resp:
                chains = [
                    item
                    for item in (await resp.json())["data"]["chains"]
                    if chains_filter is None
                    or chains_filter(await self._get_chain(item))
                ]

            sem = asyncio.Semaphore(self._threads) if self._threads else None

            async def chain_balances(chain):
                async with AsyncExitStack() as stack:
                    if sem is not None:
                        await stack.enter_async_context(sem)
                    resp = await stack.enter_async_context(
                        self._api_request(
                            "get",
                            CHAIN_BALANCE_API_URL.format(address=address, chain=chain),
                        )
                    )
                    return (await resp.json())["data"]

            # load balances for allowed chains only
            balances = await asyncio.gather(
                *[
                    chain_balances(chain)
                    for chain in chains
                    if chains_filter is None
                    or chains_filter(await self._get_chain(chain))
                ]
            )
            data = list(itertools.chain(*balances))

        result = defaultdict(list)
        for item in data:
            balance = await self._format_balance_output(
                item, chain := await self._get_chain(item["chain"])
            )
            if balance is not None:
                result[chain].append(balance)
        return result

    async def get_nft(self, address: str) -> list:
        # TODO: add functionality
        return []

    async def get_projects(self, address: str) -> list:
        # TODO: add functionality
        return []
