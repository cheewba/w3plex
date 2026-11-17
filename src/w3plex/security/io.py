"""Compatibility import for files.io."""

import sys

from .files import io as _module
from .files.io import *

sys.modules[__name__] = _module
