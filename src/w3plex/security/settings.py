"""Compatibility alias; the consumer implementation lives in w3plex.w3.settings."""

import sys
from typing import TYPE_CHECKING

from ..w3 import settings as _implementation

if TYPE_CHECKING:
    from ..w3.settings import *

sys.modules[__name__] = _implementation
