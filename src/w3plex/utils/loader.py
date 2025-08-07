from typing import (
    Optional, Callable, NamedTuple, Union, overload,
    Unpack, NotRequired, TypedDict
)

from w3ext import Account

from .filter import TemplateFilter


class FileLoaderConfig(TypedDict):
    file: str
    filter: NotRequired[str]


class FileLoader[T]:
    def __init__(self, **config: Unpack[FileLoaderConfig]):
        self.config = config

    def __call__(self, *args, **kwargs):
        return self.process(*args, **kwargs)

    @overload
    async def process(self) -> str: ...
    async def process(self, fn: Optional[Callable[[Union[str, NamedTuple]], T]] = None) -> T:
        fn = fn or (lambda item: item)

        flt = (TemplateFilter(_f) if (_f := self.config.get('filter')) is not None else
               lambda line: True)

        with open(self.config['file'], 'r', encoding='utf-8-sig') as fr:
            return [val for line in fr.readlines()
                    if flt(line=line) and (val := self.process_line(line.strip(), fn)) is not None]

    def process_line(self, line: str, fn: Callable[[Union[str, NamedTuple]], T]) -> T:
        return fn(line)


def accounts_loader(**kwargs: Unpack[FileLoaderConfig]) -> Callable[[], FileLoader[Account]]:
    def wrapper():
        return FileLoader(**kwargs)(lambda item: Account.from_key(item))
    return wrapper