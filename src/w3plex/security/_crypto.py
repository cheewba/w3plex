"""Compatibility import for crypto.primitives."""

import sys

from .crypto import primitives as _module
from .crypto.primitives import *

sys.modules[__name__] = _module
