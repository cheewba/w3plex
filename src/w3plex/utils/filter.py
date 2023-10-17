import asyncio
import re
from typing import Any, Optional, List, Callable, Tuple

from w3ext import CurrencyAmount, Chain, Currency, TokenAmount

WILDCARD = '*'


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


class TokenLookup:
    def __init__(self, template: str) -> None:
        self._template = template

    async def __call__(self, chains: List[Chain]) -> List[Tuple[Currency, Chain]]:
        chain_name, token_name = self._template.split(':')
        if token_name == WILDCARD:
            raise ValueError("wildcard for token lookup is not allowed")

        allowed_chains = [chain for chain in chains
                          if _filter_chain(chain_name)(chain)]
        tokens = await asyncio.gather(*[
            self._get_currency(chain, token_name) for chain in allowed_chains
        ])
        return list(filter(None, tokens))

    async def _get_currency(self, chain: Chain, token_name: str) -> Optional[Tuple[Currency, Chain]]:
        token = None
        if token_name.startswith('0x'):
            try:
                token = await chain.load_token(token_name)
            except:
                pass
        else:
            token = getattr(chain, token_name, None)

        return None if not token else token, chain


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
