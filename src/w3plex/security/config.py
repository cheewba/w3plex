"""Compatibility alias for the side-effect-free config reader."""

import sys

from ..config import reading as _implementation

sys.modules[__name__] = _implementation
