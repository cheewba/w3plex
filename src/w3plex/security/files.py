"""Compatibility alias; the consumer implementation lives in w3plex.w3.files."""

import sys

from ..w3 import files as _implementation

sys.modules[__name__] = _implementation
