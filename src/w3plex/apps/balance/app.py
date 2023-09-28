import asyncio
import os
import re
from collections import defaultdict
from typing import Union, List

import textwrap
from tabulate import tabulate
from termcolor import colored

from w3ext import Currency, CurrencyAmount, Account, Token
from w3plex import web3_application, apply_plugins
from w3plex.utils import get_account, get_chains, load_from_file, get_config
from w3plex.plugins import progress_bar

SEPARATOR = ', '


def is_erc_address(address: str) -> bool:
    # ethereum address length is 20 bytes = 2 + 40 chars
    return address.startswith('0x') and len(address) == 42


async def balance_of(chain_name: str, *tokens: List[Union[Currency, str]]) -> List[CurrencyAmount]:
    account, chains = get_account(), get_chains()
    chain = chains.get(chain_name)
    assert chain != None, f"Unknown chain {chain_name}"

    tokens = [token if isinstance(token, Currency)
                  else getattr(chain, token, None) or await chain.load_token(token)
              for token in tokens]

    return await asyncio.gather(
        *[chain.get_balance(account, token if isinstance(token, Token) else None)
          for token in tokens]
    )


# Custom wrap function
def _wrap_text(text, width, formatter=None):
    wrap = textwrap.TextWrapper(width=width, break_long_words=False,
                                drop_whitespace=False, break_on_hyphens=False)
    # Replace commas with comma followed by newline
    formatter = formatter or (lambda text: text)
    text = re.sub(r"\s*([^,^]+)\n([^,$]+)", r"\n\1\2", wrap.fill(text))
    return "\n".join(formatter(row) for row in text.split("\n") if row.strip())


def _format_output(accounts, result) -> str:
    # post-processing: tabulate results and summarize the total
    totals, headers, formatters = defaultdict(list), [], []
    processed = set()

    def format_row(account, item, i):
        if len(headers) == 0:
            headers.extend(item.keys())

        is_dublicate = (account_text := str(account)) in processed
        processed.add(account_text)
        formatters.append(lambda text: (colored(text, 'red') if is_dublicate else text))

        row = [account_text]
        for chain in headers:
            row.append(SEPARATOR.join(map(str, item[chain])))
            if not is_dublicate:
                # not a dublicate
                for i, balance in enumerate(item[chain]):
                    if len(totals[chain]) <= i:
                        totals[chain].append(balance)
                    else:
                        totals[chain][i] += balance
        return row
    merged = [format_row(accounts[i], row, i) for i, row in enumerate(result)]
    merged.append(["TOTAL", *[SEPARATOR.join(map(str, totals[chain]))
                              for chain in headers]])

    # to the max width also add 2 spaces and 1 char for the border
    extra_width = 3
    max_widths = [max(len(str(item)) + extra_width
                      for item in col) for col in zip(*merged)]
    terminal_width = os.get_terminal_size().columns

    # Adjust the maximum width if the total exceeds the terminal width
    if sum(max_widths) > terminal_width:
        # Scale down each max_width proportionally
        scale_factor = terminal_width / sum(max_widths)
        max_widths = [int(width * scale_factor) - extra_width
                      for width in max_widths]

    # Wrap text based on the calculated column widths
    wrapped_data = [
        [_wrap_text(str(text), max_widths[j],
                    formatters[i] if i < len(formatters) else None)
         for j, text in enumerate(row)]
        for i, row in enumerate(merged)
    ]

    return tabulate(wrapped_data, tablefmt="grid", headers=headers)


@web3_application
async def balance():
    config = get_config()

    accounts = await load_from_file(
        config['wallets'],
        lambda item, i: item if is_erc_address(item) else Account.from_key(item)
    )
    async with apply_plugins(
        progress_bar(len(accounts)),
    ):
        result = yield iter(accounts)
        print(_format_output(accounts, result))


@balance.action
async def balance_action(account):
    async def balance(chain, tokens):
        return chain, await balance_of(chain, *tokens)

    return dict(await asyncio.gather(*[
        balance(chain, tokens) for chain, tokens in get_config()['balances_of'].items()
    ]))