# W3FILE1 file format

W3FILE1 stores the encrypted content of one text or binary file. Most
applications use `encrypt_file()` and `decrypt_file()` from `w3plex.security`.
See [file encryption](file-encryption.md) for examples.

Use `w3plex.security.file_format` when working directly with the container:

```python
from w3plex.security import file_format

envelope, key = file_format.seal(data, password)
encoded = envelope.serialize()
parsed = file_format.parse(encoded)
file_key = file_format.unwrap(parsed, password)
plain = file_format.open_payload(parsed, file_key)
```

`data` and `password` are bytes. The caller sets up process protection before
handling secrets. `parse()` checks the layout and work limits; `open_payload()`
checks authentication before returning the file content.

## File layout

| Field | Size |
| --- | --- |
| Magic `W3FILE1\n` | 8 bytes |
| Header length, unsigned big-endian integer | 4 bytes |
| JSON header | 1 to 4096 bytes |
| Encrypted file key, including its tag | 48 bytes |
| Encrypted file content, including its tag | 16 bytes to 64 MiB + 16 bytes |

The header contains exactly these fields:

| Field | Value |
| --- | --- |
| `version` | Integer `1` |
| `cipher` | `AES-256-GCM` |
| `context` | `w3plex.file` |
| `file_id` | 32 lowercase hex characters |
| `salt` | 16 bytes, stored as standard Base64 |
| `wrap_nonce` | 12 bytes, stored as standard Base64 |
| `data_nonce` | 12 different bytes, stored as standard Base64 |
| `kdf` | The key derivation settings below |

Repeated JSON field names and non-finite numbers such as NaN are rejected.

## Key derivation

Argon2id creates a 32-byte password key using the password and salt. This key
encrypts a random 32-byte file key. The file key encrypts the content.

The `kdf` object contains exactly `name`, `memory_kib`, `iterations` and `lanes`:

| Setting | Default | Accepted values |
| --- | --- | --- |
| `name` | `argon2id` | `argon2id` |
| `memory_kib` | 65536 | 65536 to 262144 |
| `iterations` | 3 | 3 to 10 |
| `lanes` | 4 | 1 to 8 |

Passwords contain 1 to 4096 bytes. Size and work limits are checked before key
derivation. Each AES-256-GCM step uses its own 12-byte nonce and a 16-byte tag.
Encryption creates fresh keys, salt and nonces.

## Data checked during decryption

Both encryption steps check the header as associated data: bytes that are
checked for changes but are not encrypted. Header JSON has sorted keys, ASCII
escapes and no extra spaces.

| Step | Associated data, joined in order |
| --- | --- |
| Encrypt the file key | Magic, `\0key\0`, header JSON |
| Encrypt the content | Magic, `\0file\0`, header JSON, encrypted file key |

`\0` means a zero byte. The content check also covers the encrypted file key,
even when the reader already has a cached file key.

Wrong passwords or changed encrypted data fail without returning plaintext.
The whole content is checked before any part is returned. This format supports
up to 64 MiB of content and does not provide streaming decryption.
