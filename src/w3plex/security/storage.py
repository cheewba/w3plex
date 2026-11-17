"""Compatibility import for stores.file."""

import sys

from .stores import file as _module
from .stores.file import *

sys.modules[__name__] = _module
