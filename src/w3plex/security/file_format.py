"""Compatibility import for files.format."""

import sys

from .files import format as _module
from .files.format import *

sys.modules[__name__] = _module
