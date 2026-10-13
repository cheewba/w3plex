"""Compatibility alias; the consumer implementation lives in w3plex.w3.signing."""

import sys
from typing import TYPE_CHECKING

from ..w3 import signing as _implementation

if TYPE_CHECKING:
    from ..w3.signing import *

sys.modules[__name__] = _implementation
