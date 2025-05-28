from typing import Any

class W3PlexError(Exception):
    pass


class ConfigError(W3PlexError):
    pass


class SkipItem(Exception):
    def __init__(self, result: Any = None):
        super().__init__()
        self.result = result