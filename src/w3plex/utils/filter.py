import asyncio
import operator
import re
from collections.abc import Callable, Iterable
from typing import Any, ClassVar

from eth_typing import HexAddress, HexStr
from w3ext import Chain, Contract, Currency, CurrencyAmount, TokenAmount

WILDCARD = "*"


def _filter(fn: Callable):
    def apply_template(template: str):
        def inner(*args, **kwargs) -> bool:
            return fn(*args, **kwargs, template=template)

        return inner

    return apply_template


@_filter
def _filter_chain(chain: Chain | None, *, template: str, **kwargs) -> bool:
    if template == WILDCARD:
        return True
    return chain is not None and (
        chain.name == template or str(chain.chain_id) == template
    )


@_filter
def _filter_token(
    amount: CurrencyAmount, chain: Chain | None, *, template: str, **kwargs
) -> bool:
    if template == WILDCARD:
        return True
    success = template in (amount.currency.name, amount.currency.symbol) or (
        chain is not None and getattr(chain, template, None) == amount.currency
    )

    if isinstance(amount, TokenAmount):
        success = success or amount.currency.address.lower() == template.lower()

    return success


@_filter
def _filter_amount(amount: CurrencyAmount, *, template: str, **kwargs) -> bool:
    found = re.fullmatch(
        r"\s*(<=|>=|==|!=|<|>)\s*(\$)?([+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?)\s*",
        template,
    )
    if found is None:
        raise ValueError(f"Invalid amount condition: {template}")
    operation, usd, number = found.groups()
    value = amount.to_fixed() if usd is None else getattr(amount, "usd_price", 0)
    operations = {
        "<": operator.lt,
        "<=": operator.le,
        ">": operator.gt,
        ">=": operator.ge,
        "==": operator.eq,
        "!=": operator.ne,
    }
    return operations[operation](value, float(number))


@_filter
def _template_regexp_filter(line: str, *, template: str, **kwargs) -> bool:
    if template == WILDCARD:
        return True
    return re.match(template, line) is not None


class Filter:
    def __init__(self, template: str) -> None:
        self._filters = self.parse_filters(template)

    def parse_filters(self, template: str) -> list[Callable[..., bool]]:
        raise NotImplementedError

    def __call__(self, **kwargs: Any) -> Any:
        # joined by AND condition
        for flt in self._filters:
            if not flt(**kwargs):
                return False
        return True


class TemplateFilter(Filter):
    def parse_filters(self, template: str) -> list[Callable[..., bool]]:
        return [_template_regexp_filter(template)]


class AmountFilter(Filter):
    filters_map: ClassVar[dict[str, Callable[..., Callable[..., bool]]]] = {
        "chain": _filter_chain,
        "token": _filter_token,
        "condition": _filter_amount,
    }
    regexp = re.compile(
        r"(?P<chain>[^:\s]+):(?P<token>[^\s:<>=!]+)\s*(?P<condition>.*)"
    )

    def parse_filters(self, template: str) -> list[Callable[..., bool]]:
        found = self.regexp.fullmatch(template.strip())
        if found is None:
            raise ValueError(f"Invalid amount filter: {template}")
        parsed = found.groupdict()
        return [
            filter_(value)
            for key, filter_ in self.filters_map.items()
            if (value := parsed.get(key))
        ]


class ChainFilter(AmountFilter):
    filters_map: ClassVar[dict[str, Callable[..., Callable[..., bool]]]] = {
        "chain": _filter_chain,
    }


class ChainTemplateLookup[T]:
    def __init__(self, template: str) -> None:
        self._template = template

    async def __call__(self, chains: Iterable[Chain]) -> list[tuple[T, Chain]]:
        chain_name, *route = self._template.split(":")
        allowed_chains = [chain for chain in chains if _filter_chain(chain_name)(chain)]
        tokens = await asyncio.gather(
            *[self.get_item(chain, *route) for chain in allowed_chains]
        )
        return [token for token in tokens if token is not None]

    async def get_item(
        self, chain: Chain, item_name: str, *route: str
    ) -> tuple[T, Chain] | None:
        raise NotImplementedError


class TokenLookup(ChainTemplateLookup[Currency]):
    async def get_item(
        self, chain: Chain, item_name: str, *route: str
    ) -> tuple[Currency, Chain] | None:
        token_name = item_name
        if route:
            raise ValueError("Token lookup must have the form chain:token")
        if token_name == WILDCARD:
            raise ValueError("wildcard for token lookup is not allowed")

        token = None
        if token_name.startswith("0x"):
            try:
                token = await chain.load_token(HexAddress(HexStr(token_name)))
            except Exception:  # noqa: BLE001, S110 -- unavailable tokens are skipped
                pass
        else:
            token = getattr(chain, token_name, None)

        return (token, chain) if token is not None else None


class ContractLookup(ChainTemplateLookup[Contract]):
    def __init__(self, template: str, abi: str | None) -> None:
        super().__init__(template)
        self.abi = abi

    async def get_item(
        self, chain: Chain, item_name: str, *route: str
    ) -> tuple[Contract, Chain] | None:
        address = item_name
        if route:
            raise ValueError("Contract lookup must have the form chain:address")
        if address == WILDCARD:
            raise ValueError("wildcard for contract lookup address is not allowed")
        return chain.contract(HexAddress(HexStr(address)), abi=self.abi), chain


class ContractMethodLookup(ChainTemplateLookup[Callable[..., Any]]):
    def __init__(self, template: str, abi: str | None = None):
        super().__init__(template)
        self.abi = abi

    async def get_item(
        self, chain: Chain, item_name: str, *route: str
    ) -> tuple[Callable[..., Any], Chain]:
        if len(route) != 1 or not route[0]:
            raise ValueError(
                "Contract method lookup must have the form chain:address:method"
            )
        contract = await ContractLookup(f"*:{item_name}", self.abi).get_item(
            chain, item_name
        )
        assert contract is not None
        return getattr(contract[0].functions, route[0]), chain


def join_filters(*filters) -> Callable[..., bool]:
    def _filter(**kwargs):
        # joined by OR condition
        if not filters:
            return True
        for flt in filters:
            if flt(**kwargs):
                return True
        return False

    return _filter
