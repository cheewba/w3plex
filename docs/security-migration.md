# File encryption in w3plex 0.1

w3plex 0.1.0 removes `w3plex.secure`. File encryption, old keystores and
transparent reads now use `w3plex.security`. Existing ENC1/KS01 files remain
readable. Reading a file does not convert it to a new format.

## Update a trusted script

Import the same helpers from their new location:

```python
from w3plex.security import decrypt_file, encrypt_file

encrypted = encrypt_file("input.txt", password="PUBLIC-EXAMPLE-password")
decoded = decrypt_file(encrypted, password="PUBLIC-EXAMPLE-password")
```

The helper arguments, return types and destination rules remain the same.
`encrypt_data()` returns the base64 ciphertext and password;
`decrypt_data()` returns text. These helpers retain the old ENC1 format.
`IncorrectPassword` and `SecureError` are available from `w3plex.security`.

An import no longer changes `open()`. Enable transparent reads explicitly:

```python
from w3plex.security import disable_encrypted_io, enable_encrypted_io

context = enable_encrypted_io()
try:
    with open("keys.txt.enc", encoding="utf-8") as stream:
        text = stream.read()
finally:
    disable_encrypted_io()
    context.lock()
```

Plain files open normally. Encrypted files use keystore keys or ask for a
password. Text/binary interfaces, encodings, newlines, descriptors and ordinary
write/append/update modes keep their behavior. Writes are not automatically
encrypted. Deactivation restores the previous opener; locking clears the
context's cached keys and unlock state. Already returned plaintext stays usable.

The default context is created on first use. It reads `W3PLEX_KEYSTORE`, falling
back to `~/.keystore.bin`. It retains the standalone master/file prompts, three
read attempts and discovered-key persistence. Keystore replacement writes
ciphertext to a temporary file and replaces the target atomically. On POSIX,
that file has mode 0600. This legacy writer does not provide the new vault's
full path, concurrency or native Windows ACL guarantees.

Password requests without an interactive terminal return `interaction_required`.
They do not fall back to echoed input. Trusted noninteractive callers can pass
an explicit password or provide their own private input handler.

The `w3plex` CLI enables reads automatically, including a launch without config.
Its `encrypt`, `decrypt`, shell and application commands remain available.

## Use an independent context

```python
from w3plex.security import LegacyContext

def private_password(request):
    # Supply a trusted private input handler. Never ask the model for secrets.
    raise RuntimeError("Connect the host's private input here")

context = LegacyContext("keystore.bin", input_handler=private_password)
try:
    with context.open("keys.txt.enc", "rb") as stream:
        data = stream.read()
finally:
    context.lock()
```

These contexts keep discovered keys in their own memory and do not rewrite
source keystores during reads. They reject malformed stores and bound input
sizes. Explicit encryption methods with `add_to_keystore=True` request a write.
`compatibility=True` selects the standalone behavior, including persistent keys
and the old treatment of empty/malformed plaintext keystore JSON. Private legacy
imports in Cryptopal use the default strict mode.

Use `context.activated()` only when process-wide transparent reads are needed.
Activation rejects conflicting owners. Concurrent service contexts should use
explicit reads rather than a shared global opener.

## Protected references

Transparent reads return ordinary plaintext; they do not return secret handles.
For protected values, use [SecretStore and typed references](secret-references.md)
with the authenticated vault. That vault uses Argon2id and AES-256-GCM. ENC1/KS01
retain their historical cryptography and protection level. Moving code into
security does not strengthen old ciphertext or prevent recovery from every
memory dump. Importing into the new vault is explicit and preserves originals.
