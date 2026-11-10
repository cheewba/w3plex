# W3VAULT1 vault format

A vault stores several encrypted records and their metadata. Use `Vault` to
save, read and remove records; see [secret references](secret-references.md)
for setup and examples.

This page describes the bytes read and written by
`w3plex.security.vault_format`.

## File layout

The file starts with `W3VAULT1\n`, followed by a JSON object with exactly three
fields:

| Field | Value |
| --- | --- |
| `header` | The settings listed below |
| `wrapped_key` | The encrypted data key and its tag, stored as standard Base64 |
| `payload` | The encrypted record document and its tag, stored as standard Base64 |

The whole file can contain up to 8 MiB. The header can contain up to 4096 bytes
when encoded with sorted keys, ASCII escapes and no extra spaces. Repeated field
names, unknown format values and non-finite numbers are rejected.

| Header field | Value |
| --- | --- |
| `version` | Integer `1` |
| `cipher` | `AES-256-GCM` |
| `context` | `w3plex.vault` |
| `store_id` | 32 lowercase hex characters |
| `salt` | 16 bytes, stored as standard Base64 |
| `wrap_nonce` | 12 bytes, stored as standard Base64 |
| `data_nonce` | 12 different bytes, stored as standard Base64 |
| `kdf` | Argon2id name, memory cost, iterations and lanes |

The password and `kdf` limits match the
[W3FILE1 key derivation settings](security-file-format.md#key-derivation).

## Record document

The decrypted payload is a JSON object with one `records` list:

```json
{"records": [{"id": "0123456789abcdef0123456789abcdef", "value": "aGVsbG8="}]}
```

Each record has a unique 32-character lowercase hex ID and a Base64 value.
Other fields are record metadata. There can be up to 4096 records, each with up
to 1 MiB of decoded value bytes. A record keeps the same value and metadata for
its lifetime. To replace a value, save a new record with a new ID.

## Encryption

Argon2id creates a password key from the password and salt. AES-256-GCM uses
that key to encrypt a random 32-byte data key. The data key encrypts the record
document. Each step uses a 12-byte nonce and adds a 16-byte tag.

Associated data is checked for changes but is not encrypted. Header JSON has
sorted keys, ASCII escapes and no extra spaces.

| Step | Associated data, joined in order |
| --- | --- |
| Encrypt the data key | Header JSON without `data_nonce`, then `\0wrap` |
| Encrypt the records | Complete header JSON, `\0records\0`, encrypted data key |

`\0` means a zero byte. Leaving `data_nonce` out of the first step lets an
unlocked vault save records without keeping the password key. The second step
still checks this nonce.

Record updates use a fresh data nonce. A password change also creates a fresh
salt and data key. Unlocking checks both the data key and the record data.

## Using more than one vault instance

An unlocked instance reads the copy it loaded. Call `vault.reload()` to load
records added or removed by another instance. Reload accepts changes only for
the same store and password wrapper, and only if surviving records keep their
values and metadata. A failed reload locks the instance. A password change
requires another unlock with the new password.

`vault.delete_entries(ids)` returns removed IDs in their previous record order.
Duplicate or missing IDs are ignored. An empty selection checks whether the file
has changed without rewriting it. A stale write fails and locks the instance.
After a write error, read the file again before deciding whether to retry: the
new file may already have been written completely.

Deletion does not erase old encrypted copies or values already read by callers.
Encryption also cannot detect replacement with an older valid vault file.

## Coordinate writes across files

`CiphertextFile.writer_guard()` holds a file lock without waiting. Another
writer causes `WriterBusy`. The lock is released when the scope exits or its
process ends.

For work across several files, use one separate shared lock path. Writes to
individual files still use their own locks. Do not enter the same lock twice,
and do not remove its lock file. This lock coordinates cooperating processes;
it does not turn several file updates into one transaction.
