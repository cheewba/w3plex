"""Compatibility import for stores.format."""

import sys

from .stores import format as _module
from .stores.format import *

sys.modules[__name__] = _module
