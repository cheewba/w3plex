# File encryption

Use `w3plex.security` to encrypt files, decrypt them, or read encrypted files
through `open()`. It reads ENC1 and W3FILE1 files. Encryption helpers write
W3FILE1 files.

## Encrypt and decrypt a file

From the command line:

```sh
w3plex encrypt notes.txt --password
w3plex decrypt notes.txt.enc --password
```

`--password` without a value asks for the password privately. The first command
writes `notes.txt.enc`; the second writes `notes.txt.dec`. Use `--output PATH`
to choose another destination, or `--overwrite` to replace the source file.

In Python:

```python
from w3plex.security import decrypt_file, encrypt_file

encrypted_path = encrypt_file("notes.txt")
decrypted_path = decrypt_file(encrypted_path)
```

These calls ask for a file password when needed. Pass `password=...` if your
application already has the password from private input. Decryption checks the
complete encrypted content before writing any output.

Encrypted writes use an atomic file update. Decrypted output is written directly
to its final file, so an interrupted write can leave partial output.

## Read encrypted files with open()

Imports alone do not change Python's file handling. Enable encrypted reads when
you need them:

```python
from w3plex.security import disable_encrypted_io, enable_encrypted_io

context = enable_encrypted_io()
try:
    with open("notes.txt.enc", encoding="utf-8") as stream:
        text = stream.read()
finally:
    disable_encrypted_io()
    context.lock()
```

Plain files still open normally. Only read modes are decrypted; writes, append
modes, file descriptors and pipes pass through. `io.open()` and `Path.open()`
also keep their normal behavior.

`disable_encrypted_io()` restores the previous opener. `context.lock()` clears
cached keys. Neither call removes bytes or strings that have already been read.
The CLI enables encrypted reads automatically.

## Keep file handling local to your application

Use `context.open()` when you do not want to replace `builtins.open`:

```python
from w3plex.security import EncryptedIOContext
from w3plex.security.io import request_password


def ask_password(request):
    prompt = {
        "file": "File password: ",
        "master": "Master password: ",
        "master_confirm": "Confirm master password: ",
    }[request.kind]
    return request_password(prompt)


context = EncryptedIOContext(input_handler=ask_password)
try:
    with context.open("notes.txt.enc", "rb") as stream:
        data = stream.read()
finally:
    context.close()
```

This context keeps discovered keys in memory by default. To save them between
runs, set `keystore_path="keys.vault"` and `persist_keys=True`. You will need the
master password to unlock that store. You can also pass an existing `Vault` as
`keystore=`; close that vault separately after closing the context.

## Save and reuse file keys

The standalone helpers use one key store, at `~/.keystore.bin` by default.
`W3PLEX_KEYSTORE` or `W3PLEX_SECRET_STORE` can select another path. If both are
set, they must point to the same file.

Use `--add` with CLI encryption to save the key. Use `--keystore` with CLI
decryption to try saved keys. Python helpers provide `add_to_keystore=True` and
`use_keystore=True` for the same tasks. An explicit file password skips saved-key
lookup.

When `EncryptedIOContext` opens a selected legacy key store, it converts it to
vault format at the same path. It keeps a `.legacy.bak` backup; a plain legacy
backup is encrypted. Source data files are left unchanged by reads. Use
`LegacyContext` when you need to read or write ENC1/KS01 directly.

## Process protection and access

Modern secret operations enable process protection when needed. A host can
supply an already active `ProcessProtection` instead. On macOS, activating this
protection while a debugger is attached can end the process. Protected memory
and storage operations require the supported macOS or Linux controls.

Terminal password prompts require an interactive terminal. Other applications
can pass a password or provide an input callback. New encrypted files use mode
`0600`; your application controls access rules for existing files and folders.

For stored values that are read through references, see
[secret references](secret-references.md). For the byte layout, see the
[W3FILE1 format](security-file-format.md).
