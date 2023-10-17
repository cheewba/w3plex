from typing import Any, TypedDict, Optional, Callable, NamedTuple, Union, TypeVar

from .filter import TemplateFilter

T = TypeVar("T")

class FileLoaderConfig(TypedDict):
    file: str
    filter: Optional[str]


class FileLoader:
    def __init__(self, config: Union[FileLoaderConfig, str]) -> None:
        if isinstance(config, str):
            config = {'file': config}
        self.config = config

    async def process(self, fn: Optional[Callable[[Union[str, NamedTuple]], T]] = None) -> T:
        fn = fn or (lambda item: item)

        flt = (TemplateFilter(_f) if (_f := self.config.get('filter')) is not None else
               lambda line: True)

        with open(self.config['file'], 'r', encoding='utf-8-sig') as fr:
            return [val for line in fr.readlines()
                    if flt(line=line) and (val := self.process_line(line.strip(), fn)) is not None]

    def process_line(self, line: str, fn: Callable[[Union[str, NamedTuple]], T]) -> T:
        return fn(line)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        return self.process(*args, **kwargs)