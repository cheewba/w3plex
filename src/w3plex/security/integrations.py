"""Compatibility alias; the consumer implementation lives in w3plex.w3.integrations."""

import sys

from ..w3 import integrations as _implementation

sys.modules[__name__] = _implementation
