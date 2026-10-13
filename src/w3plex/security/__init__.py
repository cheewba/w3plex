"""Generic data protection and structural references; imports have no effects."""

from .adapters import SecretJson as SecretJson, SecretString as SecretString
from .refs import (
    ISecretRef as ISecretRef,
    SecretRef as SecretRef,
    SecretStore as SecretStore,
)
