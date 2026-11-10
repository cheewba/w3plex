# Secret references

Use `SecretStore` to save encrypted copies of values and read them later through
references. A reference keeps a record ID or a path to part of a value. It does
not keep the decrypted value between calls.

A reference backed by a `Vault` can be read only while that vault is unlocked.
Your application handles passwords, user confirmation and permission checks.

## Open a store

In this example, `master_password` is bytes received through private input.
`confirm_disclosure(request)` asks whether the value may be shown and returns
`True` only after approval.

```python
from pathlib import Path
from w3plex.security import SecretJson, SecretStore, SecretString
from w3plex.security.memory import ProcessProtection
from w3plex.security.storage import CiphertextFile
from w3plex.security.vault import Vault

protection = ProcessProtection()
protection.activate()
directory = Path.cwd() / ".secrets"
directory.mkdir(mode=0o700, exist_ok=True)
vault = Vault(CiphertextFile(directory / "data.vault"), protection=protection)
if not vault.path.exists():
    vault.create(master_password)
vault.unlock(master_password)
store = SecretStore(vault, confirm=confirm_disclosure)
```

Create process protection at application startup, before private input. On
macOS, activating it while a debugger is attached can end the process. Keep the
vault open while using the following examples, and close it when finished.

## Save and read a value

```python
source = store.capture_file("credentials.json")
api_key = SecretJson[str](source, ("debank", "api_key"))
value = api_key.ref()
```

`capture_file()` saves a copy of the file. Later changes to the source do not
change that copy. `capture(value)` saves bytes supplied by your application.
Each saved value gets its own ID.

`ref()` asks for confirmation before returning ordinary Python data. Use
`ref(silent=True)` when trusted application code needs the value without a
prompt. This does not unlock the vault or grant permission to read it.

| Reference | Value returned by ref() |
| --- | --- |
| `StoredSecret` | The saved bytes |
| `SecretString(parent, offset, length)` | Text decoded from a byte range |
| `SecretJson(parent, path)` | The JSON value at the given path |

Offsets and lengths count bytes, not text characters. `SecretString` uses UTF-8
by default. `SecretJson` accepts dictionary keys and list indexes.

To use another storage backend, implement `ISecretRef[T]` with a
`ref(*, silent=False) -> T` method. Each backend is responsible for its access
checks.

## Read encrypted sources

Pass an `EncryptedIOContext` when the source file is encrypted. The application
provides `read_private_password(request)`, returning the requested password.

```python
from w3plex.security import EncryptedIOContext

context = EncryptedIOContext(
    protection=protection,
    input_handler=read_private_password,
    keystore=vault,
)
source = store.capture_file("credentials.enc", context=context)
```

The context reads ENC1 and W3FILE1 sources. Close it before closing the borrowed
vault. For configured readers and lazy factories, see
[file loaders](async-file-capture.md).

If the YAML config itself is captured, use
`w3plex.config.load_reference_config(source, environment={}, filename=path)`.
Supply captured include files through `includes={path: reference}`. This reader
does not open include paths from disk.

## Use references in SDK objects

```python
from w3plex.w3 import Account, Debank

account = Account.from_key(SecretString(store.capture_file("key.txt")))
client = Debank(access_key=api_key)
```

Here, `key.txt` contains a hex private key. The account reads it to calculate
the address, then reads it again for each signature. DeBank reads its API key
when preparing a request. Close the DeBank client with `await client.close()`
when finished. Other SDK consumers may need a normal value from `ref()`.

## Lock, reopen and remove records

```python
vault.lock()
vault.unlock(master_password)
value = api_key.ref(silent=True)
```

Locking blocks later reads. It cannot remove data already returned to a caller.
To reopen a saved reference in another run, keep its `identifier`, open the same
vault and call `store.reference(identifier)`. Build text or JSON references from
that parent again; the source file is not read.

`vault.reload()` loads changes written by another vault instance. It keeps
unchanged references usable. If another instance changed the master password,
unlock with the new password instead.

`vault.delete_entries([identifier])` removes records and returns the removed
IDs. Other open instances see the deletion after reload or unlock. It does not
erase earlier copies of the encrypted file or data already returned to callers.

## Close resources and understand the limits

Close SDK clients first, then `context.close()` and `vault.close()`. Use
`try`/`finally` in application code so this also happens on failure. A context
closes a vault opened from its own path; a vault passed through `keystore=` must
be closed by its caller.

A saved value can contain up to 1 MiB, and a vault file up to 8 MiB. The store
checks the complete encrypted record data before returning any selected part.
Python and crypto libraries still create temporary copies in normal memory.
Locked buffers do not isolate secrets from other code in the same process or
from a privileged memory snapshot.

For file helpers, see [file encryption](file-encryption.md). For storage details,
see the [W3VAULT1 format](security-vault-format.md).
