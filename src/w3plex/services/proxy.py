import asyncio
from contextlib import asynccontextmanager

from . import Service, ServiceConfig


class ProxiesConfig(ServiceConfig):
    proxies: str


class ProxyService(Service[ProxiesConfig]):
    _proxies: asyncio.Queue[str]

    async def init(self):
        self._proxies = asyncio.Queue()
        with open(self.config['proxies'], 'r') as fr:
            for proxy in fr.readlines():
                await self._proxies.put(proxy)

    @asynccontextmanager
    async def get_proxy(self) -> str:
        try:
            proxy = await self._proxies.get()
            yield proxy
        finally:
            await self._proxies.put(proxy)
