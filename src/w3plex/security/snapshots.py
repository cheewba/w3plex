"""Compatibility import for files.snapshots."""

import sys

from .files import snapshots as _module
from .files.snapshots import *

sys.modules[__name__] = _module
