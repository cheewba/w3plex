"""Compatibility alias; the consumer implementation lives in w3plex.w3.files."""

import sys
from typing import TYPE_CHECKING

from ..w3 import files as _implementation

if TYPE_CHECKING:
    from ..w3.files import *
    from ..w3.files import _snapshot_file as _snapshot_file  # noqa: PLC0414

sys.modules[__name__] = _implementation
