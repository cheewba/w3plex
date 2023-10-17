import asyncio
import itertools
from collections import defaultdict
from contextlib import AsyncExitStack
from typing import Union, List

from rich import print
from rich.rule import Rule
from rich.columns import Columns
from rich.console import Group
from rich.padding import Padding
from rich.panel import Panel
from rich.style import Style
from rich.table import Table
from rich.text import Text

from w3ext import Currency, CurrencyAmount, Account, Token, Chain
from w3plex import application, apply_plugins
from w3plex.utils import (
    get_chains, get_config, get_services, get_context, execute_on_complete
)
from w3plex.utils.filter import AmountFilter, ChainFilter, join_filters, TokenLookup
from w3plex.utils.loader import FileLoader
from w3plex.plugins import progress_bar
from w3plex.modules.debank import Debank

empty = object()


def is_erc_address(address: str) -> bool:
    # ethereum address length is 20 bytes = 2 + 40 chars
    address = address.strip()
    return address.startswith('0x') and len(address) == 42


async def balance_of(account: str, chain: Chain,
                     *tokens: List[Union[Currency, str]]) -> List[CurrencyAmount]:
    tokens = [token if isinstance(token, Currency)
              else getattr(chain, token, None) or await chain.load_token(token)
              for token in tokens]

    return await asyncio.gather(
        *[chain.get_balance(account, token if isinstance(token, Token) else None)
          for token in tokens]
    )


def _format_output(accounts, result, _filter, show_total=True) -> str:
    duplicates = set()

    def format_row(account, item, i):
        if isinstance(item, Exception):
            # since application expect exceptions returned in result
            # lets show them for appropriate accounts
            return Padding(Text(f"{account}: {type(item).__name__}({item})", "red"),
                           (0, 0, 0, 3)), 0

        grid = Table(
            expand=True,
            # box=None,
            show_lines=True,
            show_header=False,
            show_footer=False,
            collapse_padding=True,
            pad_edge=False,
            padding=0,
            show_edge=False)
        grid.add_column(vertical='middle', min_width=30)
        grid.add_column(justify="left")

        is_duplicate = str(account) in duplicates
        account_total, account_total_shown = 0, 0
        if not is_duplicate:
            for chain, balances in item.items():
                # sort balances by USD value
                balances = sorted(balances, reverse=True,
                                key=lambda item: getattr(item, 'usd_price', 0))
                columns, chain_total, chain_total_shown = [], 0, 0
                for balance in balances:
                    chain_total += (usd_price := getattr(balance, 'usd_price', 0))
                    if (_filter is None or _filter(amount=balance, chain=chain)):
                        columns.append(Panel.fit(str(balance)))
                        chain_total_shown += usd_price

                if columns:
                    grid.add_row(
                        format_total(chain_total, chain_total_shown, f"{str(chain)}\n")
                        if chain_total_shown else str(chain),
                        Columns(columns, expand=False),
                        end_section=True
                    )
                account_total += chain_total
                account_total_shown += chain_total_shown
            duplicates.add(str(account))

        title = Text()
        title.append(str(account),
                     style=Style(bold=True, color="green" if not is_duplicate else "red",
                                 link=Debank.account_link(account)))
        if account_total:
            title.append(format_total(account_total, account_total_shown, " ", "bold"))
        return (Panel(grid, title=title, title_align='left') if grid.rows else
                Padding(title, (0, 0, 0, 3))), account_total

    def format_total(total, total_shown, title="", style=None):
        output = Text(title, style)
        if total_shown > 0:
            output.append(Text(f"${round(total_shown, 2)}", style))
        if total > 0:
            fmt = "${total}" if not total_shown else " / ${total}"
            output.append(Text(fmt.format(total=round(total, 2)), style))
        return output

    def format_all():
        total, rows = 0, []
        for i, item in enumerate(result):
            row, row_total = format_row(accounts[i], item, i)
            total += row_total
            rows.append(row)

        return Group(
            Rule(style="cyan"),
            *[Padding(row, (0, 0, 1, 0)) for row in rows],
            Padding(
                Rule(format_total(total, 0, "Total: ", "bold"),
                     style="cyan", align='left'),
                (0, 0, 1, 3)
            ),
        )

    return format_all()


@application(return_exceptions=False)
async def balance(action, input):
    if isinstance(input, str):
        # in case of input provided via cmd line,
        # check there's a string and wrap it to the iterable
        input = [input]

    ctx = get_context()
    # debank can provide filters for results,
    # so add to context the field to keep it between iterations
    ctx['result_filter'] = None

    async with apply_plugins(
        progress_bar(len(input)),
    ):
        result = yield input
        print(_format_output(input, result, ctx['result_filter']))


@balance.input
async def get_input():
    config = get_config()
    return await FileLoader(config['wallets'])(
        lambda item: item if is_erc_address(item) else Account.from_key(item).address
    )


@balance.action('onchain', default=True)
async def onchain_balance(account, config):
    async def balance(chain, tokens):
        return chain, await balance_of(account, chain, *tokens)

    chains = get_chains()
    found_tokens = itertools.chain(
        *await asyncio.gather(*[
            TokenLookup(lookup)(chains.values())
            for lookup in config.get('tokens') or []
        ])
    )
    merged = defaultdict(list)
    for token, chain in found_tokens:
        merged[chain].append(token)

    return dict(await asyncio.gather(*[
        balance(chain, tokens) for chain, tokens in merged.items()
    ]))


@balance.action('debank')
async def debank_balance(account, config, *, debank: Debank = None):
    ctx = get_context()
    if not ctx.get('result_filter'):
        filters = [AmountFilter(flt) for flt in config.get('filter') or []]
        if not filters:
            # if no filters provided, return total only
            filters.append(lambda **kwargs: not config.get('total', False))
        ctx['result_filter'] = join_filters(*filters)

    chains_filter = [ChainFilter(flt) for flt in config.get('filter') or []]
    chains_filter = join_filters(*chains_filter) if chains_filter else None
    # wrap the final filter to lambda, to be able to accept non keyword argument
    debank_filter = (lambda chain: chains_filter(chain=chain)) if chains_filter else None

    async with AsyncExitStack() as stack:
        if debank is None:
            proxy_service = (get_services(service_name)
                            if (service_name := config.get('proxy')) is not None else None)
            proxy = (await stack.enter_async_context(proxy_service.get_proxy())
                    if proxy_service is not None else None)
            debank = Debank(chains=list(get_chains().values()), proxy=proxy,
                            threads=threads if (threads := config.get('threads', empty)) is not empty else 1)
            execute_on_complete(debank.close)

        return await debank.get_balance(account, chains_filter=debank_filter,
                                        cached_only=config.get('cache_only') or False)