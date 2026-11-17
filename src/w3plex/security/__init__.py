"""Generic data protection and structural references; imports have no effects."""

import sys as _sys

from . import crypto as crypto
from .adapters import SecretJson as SecretJson, SecretString as SecretString
from .crypto import primitives as _crypto
from .files import (
    encrypted_io as encrypted_io,
    format as file_format,
    io as io,
    legacy as legacy,
    opener as file_opener,
    snapshots as snapshots,
)
from .files.encrypted_io import (
    EncryptedIOContext as EncryptedIOContext,
    PasswordRequest as PasswordRequest,
)
from .files.io import (
    decrypt_data as decrypt_data,
    decrypt_file as decrypt_file,
    disable_encrypted_io as disable_encrypted_io,
    enable_encrypted_io as enable_encrypted_io,
    encrypt_data as encrypt_data,
    encrypt_file as encrypt_file,
    unlock_keystore as unlock_keystore,
)
from .files.legacy import (
    LegacyContext as LegacyContext,
    LegacyPasswordRequest as LegacyPasswordRequest,
)
from .refs import (
    ISecretRef as ISecretRef,
    SecretBackend as SecretBackend,
    SecretStore as SecretStore,
)
from .stores import file as storage, format as vault_format, vault as vault

# Keep runtime imports of the former flat layout without separate shim files.
# New source imports use the canonical packages for static type checking.
_sys.modules.update(
    {
        f"{__name__}._crypto": _crypto,
        f"{__name__}.encrypted_io": encrypted_io,
        f"{__name__}.file_format": file_format,
        f"{__name__}.file_opener": file_opener,
        f"{__name__}.io": io,
        f"{__name__}.legacy": legacy,
        f"{__name__}.snapshots": snapshots,
        f"{__name__}.storage": storage,
        f"{__name__}.vault": vault,
        f"{__name__}.vault_format": vault_format,
    }
)
