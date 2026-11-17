"""Compatibility import for files.legacy."""

import sys

from .files import legacy as _module
from .files.legacy import *

sys.modules[__name__] = _module
