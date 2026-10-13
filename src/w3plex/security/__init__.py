"""Data protection and local secret references; imports have no policy effects.

Legacy standalone applications can continue to use ``w3plex.secure``.
Never import that compatibility module in an untrusted worker.
"""

from .refs import (
    SecretJson as SecretJson,
    SecretRef as SecretRef,
    SecretStore as SecretStore,
    SecretString as SecretString,
)
