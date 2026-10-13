"""Compatibility alias; the consumer implementation lives in w3plex.w3.settings."""

import sys

from ..w3 import settings as _implementation

sys.modules[__name__] = _implementation
