"""Shared crypto dimensions, format markers and storage defaults."""

# AES-256 data keys and password-derived wrapping keys contain 256 bits.
AES256_KEY_BYTES = 32
# Version 1 envelopes use the standard 96-bit AES-GCM nonce size.
GCM_NONCE_BYTES = 12
# AES-GCM appends a 128-bit authentication tag to each encrypted value.
GCM_TAG_BYTES = 16
# A wrapped data key contains the key ciphertext followed by its GCM tag.
WRAPPED_KEY_BYTES = AES256_KEY_BYTES + GCM_TAG_BYTES
# Modern password derivation uses a fresh 128-bit salt for each envelope.
KDF_SALT_BYTES = 16
# File, store and record identifiers contain 128 random bits before hex encoding.
IDENTIFIER_BYTES = 16
# Each identifier byte is represented by two lowercase hexadecimal characters.
IDENTIFIER_HEX_LENGTH = IDENTIFIER_BYTES * 2
# A captured snapshot must fit in one vault record, capped at 1 MiB.
MAX_RECORD_BYTES = 1024 * 1024
# Automatically generated file passwords contain 256 bits of random input.
PASSWORD_ENTROPY_BYTES = 32
# New private directories allow access only to their owner.
PRIVATE_DIRECTORY_MODE = 0o700
# New private files allow reading and writing only by their owner.
PRIVATE_FILE_MODE = 0o600
# Historical encrypted files begin with this marker before the Fernet token.
LEGACY_FILE_MAGIC = b"ENC1"
# Historical encrypted key stores place this marker after their salt.
LEGACY_STORE_MAGIC = b"KS01"
# Historical key stores prefix their payload with a 128-bit scrypt salt.
LEGACY_SALT_BYTES = 16
# Historical ENC1/KS01 Fernet keys contain 32 raw bytes before base64 encoding.
LEGACY_KEY_BYTES = 32
# Legacy key-store readers accept at most 1 MiB, including the salt and payload.
MAX_LEGACY_STORE_BYTES = 1024 * 1024
