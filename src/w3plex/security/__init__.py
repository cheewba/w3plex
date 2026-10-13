"""Generic data protection and structural references; imports have no effects."""

from .adapters import SecretJson as SecretJson, SecretString as SecretString
from .io import (
    decrypt_data as decrypt_data,
    decrypt_file as decrypt_file,
    disable_encrypted_io as disable_encrypted_io,
    enable_encrypted_io as enable_encrypted_io,
    encrypt_data as encrypt_data,
    encrypt_file as encrypt_file,
    secure_open as secure_open,
    unlock_keystore as unlock_keystore,
)
from .legacy import (
    IncorrectPassword as IncorrectPassword,
    LegacyContext as LegacyContext,
    LegacyPasswordRequest as LegacyPasswordRequest,
    SecureError as SecureError,
)
from .refs import (
    ISecretRef as ISecretRef,
    SecretStore as SecretStore,
)
