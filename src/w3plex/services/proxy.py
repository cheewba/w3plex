import asyncio
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from loguru import logger

from ..core import Service, EntityConfig


class ProxiesConfig(EntityConfig):
    proxies: str


class ProxyService(Service[ProxiesConfig]):
    _proxies: asyncio.Queue[str]

    async def init(self):
        self._proxies = asyncio.Queue()
        with open(self.config['proxies'], 'r') as fr:
            for line in fr.readlines():
                if (proxy := line.strip()):
                    await self._proxies.put(proxy)

    @asynccontextmanager
    async def get_proxy(self) -> AsyncGenerator[str, None]:
        proxy = None
        try:
            if not self._proxies.qsize():
                logger.debug("Waiting for proxy...")
            proxy = await self._proxies.get()
            yield proxy
        finally:
            if proxy is not None:
                await self._proxies.put(proxy)
