"""Compatibility alias for the side-effect-free config reader."""

import sys
from typing import TYPE_CHECKING

from ..config import reading as _implementation

if TYPE_CHECKING:
    from ..config.reading import *

sys.modules[__name__] = _implementation
