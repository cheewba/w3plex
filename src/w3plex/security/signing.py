"""Compatibility alias; the consumer implementation lives in w3plex.w3.signing."""

import sys

from ..w3 import signing as _implementation

sys.modules[__name__] = _implementation
