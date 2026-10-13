"""Compatibility alias; the consumer implementation lives in w3plex.w3.transport."""

import sys

from ..w3 import transport as _implementation

sys.modules[__name__] = _implementation
