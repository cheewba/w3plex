# Vault format V1

This is a new format for the trusted security runtime. Old `ENC1` and `KS01`
files keep their existing readers. Import preserves those source files.

A file starts with `W3VAULT1` and a newline, followed by a JSON object with exactly
three fields: `header`, `wrapped_key` and `payload`. Binary values use standard
Base64. The maximum file size is 8 MiB and the maximum canonical header size is
4 KiB. Unknown versions, duplicate fields and non-finite JSON numbers are rejected.

The header contains:

| Field | Required value |
| --- | --- |
| `version` | Integer `1` |
| `cipher` | `AES-256-GCM` |
| `context` | `w3plex.vault` |
| `store_id` | Random 128-bit identifier, lowercase hexadecimal |
| `salt` | 16 random bytes |
| `wrap_nonce` | 12 random bytes |
| `data_nonce` | 12 random bytes, distinct from the wrapping nonce |
| `kdf` | Argon2id name and integer memory/iteration/lane settings |

The default KDF uses 65,536 KiB, 3 iterations and 4 lanes. The parser accepts only
65,536–262,144 KiB, 3–10 iterations and 1–8 lanes. It checks these bounds before
starting the KDF. Passwords must be nonempty bytes, at most 4,096 bytes.

Canonical JSON sorts keys, uses compact separators and ASCII escapes, and rejects
non-finite numbers. The password-derived 256-bit key encrypts a random 256-bit
data key. AES-GCM produces a 48-byte wrapped key, including its authentication
tag. The data key encrypts the record document.

The wrapping operation authenticates the canonical header without `data_nonce`,
followed by a zero byte and `wrap`. Record encryption authenticates the complete
canonical header, `\0records\0` and the wrapped-key bytes. Excluding the changing
record nonce from the wrapping context lets an unlocked session update records
without retaining the password-derived key. The payload still authenticates that
nonce. Unlock succeeds only after both the wrapped key and payload are verified.

Every write samples a fresh nonce from the system cryptographic random source.
Immediate repeated or conflicting nonces are rejected. A password change also
generates a new salt and data key. Capturing an unlocked data key can still allow
decryption of a captured store; timeout or later rotation cannot revoke that copy.
Encryption alone cannot detect replacement with an older valid store.

`tests/fixtures/vault-v1` contains a fixed synthetic file and its generation inputs
and hash. Its password and data key are public test values. The fixture was made
with cryptography 45.0.7 Argon2id and AESGCM. Keep it fixed across codec changes;
it does not contain a real wallet or credential. Its deterministic inputs must
never be used for real storage.
