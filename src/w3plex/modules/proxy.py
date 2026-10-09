import asyncio
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager


class ProxyPool:
    """Lease file-backed proxies, returning each lease even after cancellation."""

    def __init__(self, proxies: str):
        self.filename = proxies
        self._proxies: asyncio.Queue[str] | None = None
        self._lock = asyncio.Lock()

    async def init(self):
        async with self._lock:
            if self._proxies is not None:
                return

            def read():
                with open(self.filename, encoding="utf-8-sig") as stream:
                    return [
                        line.strip()
                        for line in stream
                        if line.strip() and not line.lstrip().startswith("#")
                    ]

            values = await asyncio.to_thread(read)
            if not values:
                raise ValueError(f"No proxies found in {self.filename}")
            queue: asyncio.Queue[str] = asyncio.Queue()
            for value in values:
                queue.put_nowait(value)
            self._proxies = queue

    @asynccontextmanager
    async def get_proxy(self) -> AsyncGenerator[str, None]:
        await self.init()
        assert self._proxies is not None
        proxy = await self._proxies.get()
        try:
            yield proxy
        finally:
            self._proxies.put_nowait(proxy)
