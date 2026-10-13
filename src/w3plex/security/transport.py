"""Compatibility alias; the consumer implementation lives in w3plex.w3.transport."""

import sys
from typing import TYPE_CHECKING

from ..w3 import transport as _implementation

if TYPE_CHECKING:
    from ..w3.transport import *

sys.modules[__name__] = _implementation
