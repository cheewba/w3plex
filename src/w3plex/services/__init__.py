from typing import TypedDict, TypeVar, Generic

Cfg = TypeVar("Cfg", bound="ServiceConfig")


class ServiceConfig(TypedDict):
    service: str


class Service(Generic[Cfg]):
    def __init__(self, config: Cfg) -> None:
        self.config = config

    async def init(self):
        pass

    async def finalize(self):
        pass