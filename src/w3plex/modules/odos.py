import asyncio
import logging
from dataclasses import dataclass
from typing import List, Union, Iterable, Optional

import aiohttp
from w3ext import Chain, CurrencyAmount, Currency, Account, TokenAmount

from .module import ModuleError

logger = logging.getLogger(__name__)


QUOTE_URL = "https://api.odos.xyz/sor/quote/v2"
ASSEMBLE_URL = "https://api.odos.xyz/sor/assemble"
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
        input = ", ".join([f"{_in}({self.input_usd[i]})"
                           for i, _in in enumerate(self.input)])
        output = ", ".join([f"{_out}({self.output_usd[i]})"
                            for i, _out in enumerate(self.output)])
        return f"{self.chain}({input} -> {output})"


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
        self, output: Union["Currency", List["Currency"], List[List["Currency", float]]]
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
        } for [token, prop] in input]

    def _format_input(
        self, input: Union["CurrencyAmount", List["CurrencyAmount"]]
    ) -> List[dict]:
        input = input if isinstance(input, Iterable) else [input]
        return [{
            "tokenAddress": self._token_address(item),
            "amount": item.amount,
        } for item in input]

    def _format_quote(
        self,
        data: dict,
        input: List[Currency],
        output: List[Currency]
    ) -> Quote:
        def sort_tokens(tokens: List[Currency], addresses: List[str]):
            map = {getattr(t, "address", EMPTY_WALLET).lower() for t in tokens}
            return [map[addr.lower()] for addr in addresses]

        def to_amounts(tokens: List[Currency], amounts: List[str]):
            return [token.to_amount(int(amounts[i])) for i, token in enumerate(tokens)]

        usd = Currency('USD', 'USD', 2)
        return Quote(
            chain=self.chain,
            input=to_amounts(sort_tokens(input, data["inTokens"]), data['inAmounts']),
            input_usd=to_amounts([usd] * len(in_usd := data["inValues"]), in_usd),
            output=to_amounts(sort_tokens(output, data["outTokens"]), data['outAmounts']),
            output_usd=to_amounts([usd] * len(out_usd := data["outValues"]), out_usd),
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

        headers = {
            "Content-Type": "application/json"
        }
        async with self._session as session:
            async with session.post(ASSEMBLE_URL, data=data, headers=headers) as resp:
                if not resp.status == 200:
                    raise ModuleError(f"{self.name}: Assemble swap tx error `{resp.reason}`")
                return await resp.json()

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

        need_permissions: List["TokenAmount"] = await asyncio.gather(*[
            get_required(amount) for amount in input
        ])
        if len(need_permissions) == 0:
            return False

        nonce: int = await self.chain.get_nonce()
        await asyncio.gather(*[approve(amount) for amount in need_permissions])

        return True

    async def get_quote(
        self,
        input: Union["CurrencyAmount", List["CurrencyAmount"]],
        output: Union["Currency", List["Currency"], List[List["Currency", float]]],
        slippage: float = 0.5
    ) -> Quote:
        data = {
            "chainId": self.chain.chain_id,
            "inputTokens": self._format_input(input),
            "outputTokens": self._format_output(output),
            "slippageLimitPercent": slippage,
            "userAddr": self.account.address,
            "referralCode": self.ref_code or 0,
            "compact": True
        }

        headers = {
            "Content-Type": "application/json"
        }
        async with self._session as session:
            async with session.post(QUOTE_URL, data=data, headers=headers) as resp:
                if not resp.status == 200:
                    raise ModuleError(f"{self.name}: Get quote error `{resp.reason}`")
                return self._format_quote(await resp.json())

    async def swap(self, quote: Quote):
        tx_data = await self._build_swap_tx(quote)

        if await self._check_permissions(quote.input, self.account.address, tx_data['to']):
            # if we sent some permissions tx's, it might be better to
            # get new transaction data to be sure it's up to date
            tx_data = await self._build_swap_tx(quote)

        tx_hash = self.chain.send_transaction(tx_data, self.account)
        logger.info(f"{self.name}: Swap transaction sent: {self.chain.get_tx_scan(tx_hash)}")

        return await self.chain.wait_for_transaction_receipt(tx_hash)
