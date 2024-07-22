import asyncio
import re
from typing import Any, Optional, List, Callable, Tuple, Generic, TypeVar

from w3ext import CurrencyAmount, Chain, Currency, TokenAmount, Contract

WILDCARD = '*'

T = TypeVar("T")


def _filter(fn: Callable):
    def apply_template(template: str):
        def inner(*args, **kwargs) -> bool:
            return fn(*args, **kwargs, template=template)
        return inner

    return apply_template


@_filter
def _filter_chain(chain: Optional[Chain], *, template: str, **kwargs) -> bool:
    if template == WILDCARD:
        return True
    return (chain is not None and
            (chain.name == template or chain.chain_id == template))


@_filter
def _filter_token(amount: CurrencyAmount, chain: Optional[Chain], *, template: str, **kwargs) -> bool:
    if template == WILDCARD:
        return True
    success = (amount.currency.name == template
               or (chain and getattr(chain, template, None) == amount.currency))

    if isinstance(amount, TokenAmount):
        success = success or amount.currency.address.lower() == template.lower()

    return success


@_filter
def _filter_amount(amount: CurrencyAmount, *, template: str, **kwargs) -> bool:
    if (re.search(r";", template)):
        raise ValueError(f"Unsafe filter found: `{template}`")

    template, was_usd = re.subn(r"\$([\d.]+)", r"\1", template)
    amount = amount.to_fixed() if not was_usd else getattr(amount, 'usd_price', 0)

    # TODO: it might be unsafe, so maybe more checks should be added
    return bool(eval(f"amount {template}", {}, {'amount': amount}))


@_filter
def _template_regexp_filter(line: str, *, template: str, **kwargs) -> bool:
    if template == WILDCARD:
        return True
    return re.match(template, line) is not None


class Filter:
    def __init__(self, template: str) -> None:
        self._filters = self.parse_filters(template)

    def parse_filters(self, template: str) -> List[Callable[[List[Any]], bool]]:
        raise NotImplementedError

    def __call__(self, **kwargs: Any) -> Any:
        # joined by AND condition
        for flt in self._filters:
            if (not flt(**kwargs)):
                return False
        return True


class TemplateFilter(Filter):
    def parse_filters(self, template: str) -> List[Callable[[List[Any]], bool]]:
        return [_template_regexp_filter(template)]


class AmountFilter(Filter):
    filters_map = {
        'chain': _filter_chain,
        'token': _filter_token,
        'condition': _filter_amount
    }
    regexp = re.compile(r"(?P<chain>[^:]+):(?P<token>[\w\d*]+)(?P<condition>.*$)")

    def parse_filters(self, template: str) -> List[Callable[[List[Any]], bool]]:
        found = self.regexp.search(template)
        if found is None:
            return[]
        parsed = found.groupdict()
        return [
            filter_(value)
            for key, filter_ in self.filters_map.items()
            if (value := parsed.get(key))
        ]


class ChainFilter(AmountFilter):
    filters_map = {
        'chain': _filter_chain,
    }

class ChainTemplateLookup(Generic[T]):
    def __init__(self, template: str) -> None:
        self._template = template

    async def __call__(self, chains: List[Chain]) -> List[Tuple[T, Chain]]:
        chain_name, *route = self._template.split(':')
        allowed_chains = [chain for chain in chains
                          if _filter_chain(chain_name)(chain)]
        tokens = await asyncio.gather(*[
            self.get_item(chain, *route) for chain in allowed_chains
        ])
        return list(filter(None, tokens))

    async def get_item(self, chain, *route):
        raise NotImplementedError


class TokenLookup(ChainTemplateLookup[Currency]):
    async def get_item(self, chain: Chain, token_name: str) -> Optional[Tuple[Currency, Chain]]:
        if token_name == WILDCARD:
            raise ValueError("wildcard for token lookup is not allowed")

        token = None
        if token_name.startswith('0x'):
            try:
                token = await chain.load_token(token_name)
            except Exception:
                pass
        else:
            token = getattr(chain, token_name, None)

        return None if not token else token, chain


class ContractLookup(ChainTemplateLookup):
    def __init__(self, template: str, abi: Optional[str]) -> None:
        super().__init__(template)
        self.abi = abi

    async def get_item(self, chain: Chain, address: str) -> Optional[Tuple[Contract, Chain]]:
        if address == WILDCARD:
            raise ValueError("wildcard for contract lookup address is not allowed")
        return chain.contract(address)


class ContractMethodLookup(ContractLookup):
    pass


def join_filters(*filters) -> Callable[[CurrencyAmount, Optional[Chain]], bool]:
    def _filter(**kwargs):
        # joined by OR condition
        if not filters:
            return True
        for flt in filters:
            if (flt(**kwargs)):
                return True
        return False
    return _filter
