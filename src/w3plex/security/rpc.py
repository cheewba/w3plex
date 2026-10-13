"""Compatibility alias; the consumer implementation lives in w3plex.w3.rpc."""

import sys

from ..w3 import rpc as _implementation

sys.modules[__name__] = _implementation
