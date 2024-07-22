from typing import Generic, TypeVar, Unpack, TypedDict, Callable, overload

from lazyplex import Application, application as _application


T = TypeVar('T')
Cfg = TypeVar('Cfg', bound="EntityConfig")

@overload
def application(fn: Callable) -> Application: ...
@overload
def application(*, return_exceptions: bool = False) -> Callable[[Callable], Application]: ...

def application(*args, **kwargs):
    """ Wrapper around ``lazyplex.application`` that accepts function as argument only.

        Threre's no need to pass name of the application, since
        it's taken from the config file.
    """
    kwargs['application_class'] = Application
    if args and isinstance(args[0], Callable):
        return _application(**kwargs)(args[0])
    return _application(*args, **kwargs)


class EntityConfig(TypedDict):
    __init__: str


class Entity(Generic[Cfg]):
    config: Cfg

    def __init__(self, **config: Unpack[Cfg]) -> None:
        self.config = config


class CallableEntity(Generic[Cfg, T], Entity[Cfg]):
    def __call__(self, *args, **kwargs) -> T:
        return self.process(*args, **kwargs)

    async def process(self, *args, **kwargs) -> T:
        raise NotImplementedError



class Loader(Generic[Cfg, T], CallableEntity[Cfg, T]):
    pass


class Filter(Generic[Cfg], CallableEntity[Cfg, bool]):
    pass


class Condition(Generic[Cfg, T], CallableEntity[Cfg, T]):
    pass


class Service(Generic[Cfg], Entity[Cfg]):
    async def init(self):
        pass

    async def finalize(self):
        pass