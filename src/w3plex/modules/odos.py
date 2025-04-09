import asyncio
import logging
from dataclasses import dataclass
from typing import List, Union, Iterable, Optional, Tuple

import aiohttp
from w3ext import Chain, CurrencyAmount, Currency, Account, TokenAmount

from .module import ModuleError

logger = logging.getLogger(__name__)


QUOTE_URL = "https://api.odos.xyz/sor/quote/v2"
ASSEMBLE_URL = "https://api.odos.xyz/sor/assemble"
GAS_PRICE_URL = "https://api.odos.xyz/gas/price/{chain_id}"
EMPTY_WALLET = f"0x{'0' * 40}"

@dataclass
class Quote:
    chain: Chain
    input: List[CurrencyAmount]
    input_usd: List[CurrencyAmount]
    output: List[CurrencyAmount]
    output_usd: List[CurrencyAmount]
    path_id: str
    gas_limit: int
    price_impact: float

    def __str__(self) -> str:
        input_ = ", ".join([f"{_in} ({self.input_usd[i]})"
                           for i, _in in enumerate(self.input)])
        output_ = ", ".join([f"{_out} ({self.output_usd[i]})"
                            for i, _out in enumerate(self.output)])
        return f"{self.chain}: {input_} -> {output_}"


class OdosError(ModuleError):
    pass


class TransactionFailed(OdosError):
    pass


class Odos:
    name = "odos"

    def __init__(
        self,
        account: "Account",
        chain: "Chain",
        ref_code: Optional[str] = None
    ) -> None:
        self.account = account
        self.chain = chain
        self.ref_code = ref_code

        # setup session default args
        self._session = aiohttp.ClientSession()

    def _token_address(self, item: Union["Currency", "CurrencyAmount"]) -> str:
        if isinstance(item, CurrencyAmount):
            return self._token_address(item.currency)
        return getattr(item, 'address', EMPTY_WALLET)

    def _format_output(
        self, output: Union["Currency", List["Currency"], List[Tuple["Currency", float]]]
    ) -> List[dict]:
        if isinstance(output, Currency):
            output = [[output, 1]]
        else:
            total, count = 1, len(output)
            for idx, el in enumerate(output):
                if idx == 0 and not isinstance(el, Currency):
                    # seems like that's an List[List["Currency", float]]
                    break
                output[idx] = [el, prop := (round(total / count - idx, 2) if idx < count - 1 else total)]
                total -= prop

        return [{
            "tokenAddress": self._token_address(token),
            "proportion": prop
        } for [token, prop] in output]

    def _format_input(
        self, input: Union["CurrencyAmount", List["CurrencyAmount"]]
    ) -> List[dict]:
        input = input if isinstance(input, Iterable) else [input]
        return [{
            "tokenAddress": self._token_address(item),
            "amount": str(item.amount),
        } for item in input]

    def _format_quote(
        self,
        data: dict,
        input_: List[Currency],
        output_: List[Currency]
    ) -> Quote:
        def sort_tokens(tokens: List[Currency], addresses: List[str]):
            map = {getattr(t, "address", EMPTY_WALLET).lower(): t for t in tokens}
            return [map[addr.lower()] for addr in addresses]

        def to_amounts(tokens: List[Currency], amounts: List[str]):
            return [token.to_amount(int(amounts[i])) for i, token in enumerate(tokens)]

        usd = Currency('USD', 'USD', (usd_decimals := 2))
        return Quote(
            chain=self.chain,
            input=to_amounts(sort_tokens(input_, data["inTokens"]), data['inAmounts']),
            input_usd=to_amounts([usd] * len(in_usd := data["inValues"]),
                                 [item * 10 ** usd_decimals for item in in_usd]),
            output=to_amounts(sort_tokens(output_, data["outTokens"]), data['outAmounts']),
            output_usd=to_amounts([usd] * len(out_usd := data["outValues"]),
                                  [item * 10 ** usd_decimals for item in out_usd]),
            gas_limit=data["gasEstimate"],
            price_impact=data["priceImpact"],
            path_id=data["pathId"]
        )

    async def _build_swap_tx(self, quote: Quote):
        data = {
            "userAddr": self.account.address,
            "pathId": quote.path_id,
            "simulate": False,
        }
        return await self._api_request('post', ASSEMBLE_URL, json=data)

    async def _check_permissions(self, input: List["CurrencyAmount"], owner: str, spender: str) -> bool:
        async def get_required(amount: "CurrencyAmount") -> Optional["CurrencyAmount"]:
            if not isinstance(amount, TokenAmount):
                return None
            allowance = await amount.currency.get_allowance(owner, spender)
            if allowance >= amount:
                return None
            return amount

        def approve(amount: "TokenAmount"):
            nonlocal nonce
            old_nonce, nonce = nonce, nonce + 1
            return amount.currency.approve(self.account, spender, amount,
                                           {"nonce": old_nonce})

        need_permissions: List["TokenAmount"] = list(filter(bool, await asyncio.gather(*[
            get_required(amount) for amount in input
        ])))
        if len(need_permissions) == 0:
            return False

        nonce: int = await self.chain.get_nonce(self.account.address)
        tx_hashes = await asyncio.gather(
            *[approve(amount) for amount in need_permissions])
        await asyncio.gather(
            *[self.chain.wait_for_transaction_receipt(tx_hash)
              for tx_hash in tx_hashes]
        )
        return True

    async def get_session(self) -> aiohttp.ClientSession:
        if not self._session:
            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
            self._session = aiohttp.ClientSession(headers=headers)
        return self._session

    async def _api_request(self, method, url, **kwargs):
        session = await self.get_session()
        async with session.request(method, url, **kwargs) as resp:
            if resp.status not in {200, 201}:
                msg = (f"{self.name}: Api request error to {url} "
                       f"`{resp.status} - {resp.reason}`")
                raise OdosError(msg)
            return await resp.json()

    async def get_gas_price(self):
        response = await self._api_request(
            'get', GAS_PRICE_URL.format(chain_id=self.chain.chain_id)
        )
        gas_price = response.get('baseFee') or 0
        if not gas_price:
            prices = response.get('prices')
            if prices:
                gas_price = int(sum([price['fee'] for price in prices]) / len(prices))
        return gas_price

    async def get_quote(
        self,
        input_: Union["CurrencyAmount", List["CurrencyAmount"]],
        output_: Union["Currency", List["Currency"], List[Tuple["Currency", float]]],
        slippage: float = 0.5
    ) -> Quote:
        data = {
            "chainId": int(self.chain.chain_id),
            "inputTokens": self._format_input(input_),
            "outputTokens": self._format_output(output_),
            "slippageLimitPercent": slippage,
            "userAddr": self.account.address,
            "referralCode": self.ref_code or 1,
            "gasPrice": await self.get_gas_price(),
            "disableRFQs": False,
            "likeAsset": True,
            "compact": True,
            "pathViz": False,
            "sourceBlacklist": [],
        }

        resp = await self._api_request('post', QUOTE_URL, json=data)
        return self._format_quote(
            resp,
            [item.currency
                for item in ([input_] if isinstance(input_, CurrencyAmount) else input_)],
            ([output_] if isinstance(output_, Currency)
                else [item if isinstance(item, Currency) else item[0] for item in output_])
        )

    async def swap(self, quote: Quote):
        tx_data = (await self._build_swap_tx(quote))["transaction"]

        if await self._check_permissions(quote.input, self.account.address, tx_data['to']):
            # if we sent some permissions tx's, it might be better to
            # get new transaction data to be sure it's up to date
            tx_data = (await self._build_swap_tx(quote))["transaction"]

        tx_hash = await self.chain.send_transaction(tx_data, self.account)
        logger.info(f"{self.name}: Swap transaction sent: {self.chain.get_tx_scan(tx_hash)}")

        receipt = await self.chain.wait_for_transaction_receipt(tx_hash)
        if receipt.status != 1:
            raise TransactionFailed(f"{self.name}: Swap error: {receipt.status}")
        return receipt