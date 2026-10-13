"""Generic data protection and structural references; imports have no effects."""

from .adapters import SecretJson as SecretJson, SecretString as SecretString
from .encrypted_io import (
    EncryptedIOContext as EncryptedIOContext,
    PasswordRequest as PasswordRequest,
)
from .io import (
    decrypt_data as decrypt_data,
    decrypt_file as decrypt_file,
    disable_encrypted_io as disable_encrypted_io,
    enable_encrypted_io as enable_encrypted_io,
    encrypt_data as encrypt_data,
    encrypt_file as encrypt_file,
    unlock_keystore as unlock_keystore,
)
from .legacy import (
    LegacyContext as LegacyContext,
    LegacyPasswordRequest as LegacyPasswordRequest,
)
from .refs import (
    ISecretRef as ISecretRef,
    SecretStore as SecretStore,
)
