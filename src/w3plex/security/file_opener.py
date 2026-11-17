"""Compatibility import for files.opener."""

import sys

from .files import opener as _module
from .files.opener import *

sys.modules[__name__] = _module
