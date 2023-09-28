import asyncio
from typing import Optional, Dict

from w3ext import Chain
from lazyplex import application as _application, Application as _Application

from .constants import CONTEXT_CHAINS_KEY, CONTEXT_EXTRAS_KEY, CONTEXT_CONFIG_KEY


class Web3Application(_Application):
    """ Extended version of ``lazyplex.Application``

        It processes some additional data initializations,
        that are common for all web3 applications
    """
    async def _load_chain(
        self, name: str, *,
        erc20: Optional[dict] = None,
        **chain_info
    ) -> Dict[str, "Chain"]:
        chain = await Chain.connect(**chain_info)
        if (erc20):
            await asyncio.gather(*[chain.load_token(token, cache_as=key)
                                   for key, token in erc20.items()])
        return name, chain

    async def _add_chains(self, ctx: Dict):
        # in case there's a chains setting in app config, use it
        # to narrow down the number of loaded chains
        allowed = (ctx.get(CONTEXT_CONFIG_KEY) or {}).get('chains')
        chains = ctx.get(CONTEXT_EXTRAS_KEY, {}).get('chains') or {}
        ctx[CONTEXT_CHAINS_KEY] = dict(await asyncio.gather(
            *(self._load_chain(name, **info) for name, info in chains.items()
              if allowed is None or name in allowed)
        ))
        return ctx

    async def run(self, ctx: Optional[Dict] = None):
        ctx = await self._add_chains(ctx or {})
        return await super().run(ctx)


def application(fn):
    """ Wrapper around ``lazyplex.application`` that accepts function as argument only.

        Threre's no need to pass name of the application, since
        it's taken from the config file.
    """
    return _application(fn)


def web3_application(fn):
    """ Wrapper around ``lazyplex.application`` with some additional config initializations. """
    return Web3Application(fn)
