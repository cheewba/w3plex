# Byte encryption and custom storage

`w3plex.security.crypto` provides AES-256-GCM byte encryption, Argon2id password
keys and HKDF-SHA256 subkeys. These operations have no file paths, record schema,
password prompts or global I/O changes. Existing W3FILE1 and W3VAULT1 formats use
the same encryption and password-key operations, preserving their byte layouts.

## Package layout

- `crypto`: byte encryption, encoded blocks and key derivation.
- `files`: encrypted-file contexts, formats, snapshots and standalone I/O.
- `stores`: encrypted record vaults, their format and checked file persistence.
- `refs`, `adapters`, `memory`, `errors` and `diagnostics`: shared reference and
  protection contracts.

New code can import `Vault` from `w3plex.security.stores.vault`, file contexts
from `w3plex.security.files.encrypted_io` and helpers from
`w3plex.security.files.io`. Existing module paths, including
`w3plex.security.vault`, `storage`, `encrypted_io` and `file_format`, remain
runtime aliases of the same implementations, registered in `security/__init__.py`
without separate forwarding files. Use canonical package paths in new source
for static type checking. The public `crypto` API and top-level exports keep
their existing paths. No import activates encrypted I/O.

## Encrypt a block

The application supplies bytes and an authenticated public context. Text, JSON
and YAML serialization belong to the caller. `seal()` generates a fresh random
nonce; `unseal()` authenticates the entire ciphertext and context before returning
plaintext. A wrong key, changed context or changed ciphertext raises
`AuthenticationFailed` without returning any part of the value.

```python
from w3plex.security import crypto
from w3plex.security.memory import LockedBuffer, ProcessProtection

protection = ProcessProtection()
protection.activate()  # Before private input; see the platform limits below.
with LockedBuffer(crypto.generate_key(), protection=protection) as key:
    block = crypto.seal(
        b"PUBLIC-TEST-example", key=key.copy_bytes(), context=b"example/value/v1"
    )
    saved = block.to_data()
    restored = crypto.EncryptedBlock.from_data(saved)
    value = crypto.unseal(
        restored, key=key.copy_bytes(), context=b"example/value/v1"
    )
```

`EncryptedBlock` contains only a nonce and ciphertext with its authentication tag.
`to_data()` encodes both as base64 strings in a dictionary; `from_data()` validates
their representation. The caller chooses the containing document and its version.
Context bytes must be identical when reading. Use an unambiguous encoding of the
project ID, record ID and purpose when composing contexts from several fields.

`encrypt_aead()` and `decrypt_aead()` are the lower-level operations used by the
existing formats. They take an explicit nonce and authenticated associated data.
Prefer `seal()` for new application code; never reuse a nonce with the same key.

## Password keys and subkeys

`derive_password_key(password, salt=salt, settings=settings)` accepts password
bytes, a random salt from `generate_salt()` and `KdfSettings()`. Persist the salt
and `settings.to_data()` alongside the encrypted data; restore settings with
`KdfSettings.from_data()`. Work limits are checked before derivation. Keep these
public parameters accessible before decrypting the data they protect.

`derive_subkey(project_key, salt=salt, context=context)` accepts a strong random
AES-256 key, never a password. It returns a deterministic subkey for the supplied
salt and context. Persist the salt and use different purposes for a record value
and its containing catalog. Salts randomize derivation; they do not replace
encryption nonces.

A custom application can compose independently encrypted records and a catalog:

1. Generate or unlock its project key.
2. Derive a record key and call `seal()` for the value.
3. Serialize the record's salt, context/ID, metadata and encrypted block.
4. Derive a catalog key and call `seal()` for those serialized bytes.
5. Store the outer block in its YAML `_storage` field.

Reading reverses these steps. After opening the catalog, record values can remain
encrypted until requested. The application supplies the document layout and safe,
atomic YAML updates; it does not need to implement cryptographic algorithms.

## Reuse secret references

`SecretStore(backend, confirm=callback)` accepts the structural `SecretBackend`
protocol. Existing `SecretStore(vault)` calls remain supported, including the
`vault=` keyword. A backend provides:

- `checkpoint()`: an opaque session token; reject access when locked.
- `guard(checkpoint)`: validate the token on entry and exit, and serialize the
  enclosed work against lock/unlock. Each operation enters it once.
- `validate_identifier(identifier)`: validate its own opaque string IDs.
- `save(value)` and `read(identifier)`: save immutable bytes and read them later.

The backend owns key lifetime and synchronization. Its guard must not silently
accept a new session, even if it was locked and reopened with the same password.
Confirmation runs outside the guard so locking can interrupt user input.
`SecretStore` retains its 1 MiB capture limit and handles disclosure confirmation,
safe errors and references. `SecretString` and `SecretJson` work on those references
without knowing the backend. Set a capture callback with `using_file_opener()`
to use them with Runner and FileLoader; see [file loaders](async-file-capture.md).

## Ownership and compatibility

The byte API returns normal Python bytes. Retain keys in `LockedBuffer` when
needed, close owned buffers explicitly, and avoid retaining decrypted values.
Closing a buffer cannot erase copies already returned to Python or crypto code.
Process protection currently requires supported macOS/Linux controls; activating
it while a debugger is attached on macOS can end the process. The byte primitives
do not activate it implicitly and do not isolate code within the same process.

Block encryption alone does not implement sessions, record immutability, file
locking or rollback detection. Those remain responsibilities of the chosen store.
Existing vault and encrypted-file APIs retain their formats, legacy migration,
explicit I/O activation and resource ownership. This API adds no dependencies.
