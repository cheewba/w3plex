import asyncio
from contextlib import asynccontextmanager
from typing import AsyncGenerator, TypedDict, Unpack, Optional

from ..logging import logger
from ..utils import deprecated


class ProxiesConfig(TypedDict):
    proxies: str


@deprecated("use w3plex.modules.proxy instead")
class ProxyService:
    def __init__(self, **config: Unpack[ProxiesConfig]):
        self.config = config
        self._proxies: Optional[asyncio.Queue[str]] = None

    async def init(self):
        self._proxies = asyncio.Queue()
        with open(self.config['proxies'], 'r') as fr:
            for line in fr.readlines():
                if (proxy := line.strip()):
                    await self._proxies.put(proxy)

    @asynccontextmanager
    async def get_proxy(self) -> AsyncGenerator[str, None]:
        if self._proxies is None:
            await self.init()

        proxy = None
        try:
            if not self._proxies.qsize():
                logger.debug("Waiting for proxy...")
            proxy = await self._proxies.get()
            yield proxy
        finally:
            if proxy is not None:
                await self._proxies.put(proxy)
