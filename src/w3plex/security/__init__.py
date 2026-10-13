"""Data protection and local secret references; imports have no policy effects.

Legacy standalone applications can continue to use ``w3plex.secure``.
Never import that compatibility module in an untrusted worker.
"""

from .refs import SecretJson as SecretJson
from .refs import SecretRef as SecretRef
from .refs import SecretStore as SecretStore
from .refs import SecretString as SecretString
