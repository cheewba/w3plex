"""Compatibility alias; the consumer implementation lives in w3plex.w3.integrations."""

import sys
from typing import TYPE_CHECKING

from ..w3 import integrations as _implementation

if TYPE_CHECKING:
    from ..w3.integrations import *

sys.modules[__name__] = _implementation
