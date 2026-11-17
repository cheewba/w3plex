"""Compatibility import for files.encrypted_io."""

import sys

from .files import encrypted_io as _module
from .files.encrypted_io import *

sys.modules[__name__] = _module
