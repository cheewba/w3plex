import asyncio
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import TypedDict, Unpack

from ..log import logger
from ..utils import deprecated


class ProxiesConfig(TypedDict):
    proxies: str


@deprecated("use w3plex.modules.proxy instead")
class ProxyService:
    def __init__(self, **config: Unpack[ProxiesConfig]):
        self.config = config
        self._proxies: asyncio.Queue[str] | None = None

    async def init(self):
        self._proxies = asyncio.Queue()

        def read_lines():
            with open(self.config["proxies"], "r") as fr:
                return list(fr)

        for line in await asyncio.to_thread(read_lines):
            if proxy := line.strip():
                await self._proxies.put(proxy)

    @asynccontextmanager
    async def get_proxy(self) -> AsyncGenerator[str, None]:
        if self._proxies is None:
            await self.init()
        proxies = self._proxies
        assert proxies is not None

        proxy = None
        try:
            if not proxies.qsize():
                logger.debug("Waiting for proxy...")
            proxy = await proxies.get()
            yield proxy
        finally:
            if proxy is not None:
                await proxies.put(proxy)
