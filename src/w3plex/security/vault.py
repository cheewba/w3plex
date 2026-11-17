"""Compatibility import for stores.vault."""

import sys

from .stores import vault as _module
from .stores.vault import *

sys.modules[__name__] = _module
