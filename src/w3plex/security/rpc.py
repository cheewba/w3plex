"""Compatibility alias; the consumer implementation lives in w3plex.w3.rpc."""

import sys
from typing import TYPE_CHECKING

from ..w3 import rpc as _implementation

if TYPE_CHECKING:
    from ..w3.rpc import *

sys.modules[__name__] = _implementation
