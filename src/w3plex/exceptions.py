class W3PlexError(Exception):
    pass


class ConfigError(W3PlexError):
    pass


class SkipItem(Exception):
    pass