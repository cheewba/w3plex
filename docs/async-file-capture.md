# File loaders

`FileLoader` reads a file line by line. It skips blank lines and comments and
can apply a regular-expression filter. Without an opener, it returns strings
and reads the file again on each call.

For protected data, provide an opener that returns `ISecretRef[bytes]`. The
opener can be a normal or async function. A successful capture is kept, so later
calls use the same saved bytes even if the source file changes or is removed.

The examples below use the `store` and `context` described in
[secret references](secret-references.md).

## Create a reader

```python
from functools import partial
from w3plex.utils.loader import FileLoader, using_file_opener

capture = partial(store.capture_file, context=context)
with using_file_opener(capture):
    reader = FileLoader(file="keys.enc")

lines = await reader()
```

The reader keeps the opener that was set when it was created. It still works
after leaving the `with` block. Captured files return `SecretString` line
references, so a transform passed to `reader.process(fn)` must accept them.

You can also pass an existing reference as `file`. It is used directly, without
calling the opener. `using_file_opener(None)` creates readers that use ordinary
file reads inside that scope.

## Use loaders from config

Set the opener context while initializing a runner:

```python
with using_file_opener(capture):
    await runner.init(config, config_path)
```

The runner keeps this opener for application calls after the block ends. It
borrows the opener; the application remains responsible for closing it. The
`file_opener` argument to `Runner.init()` has been replaced by this context.

Without an opener in the context, each runner creates its own default opener.
That opener detects ordinary, ENC1 and W3FILE1 sources. Ordinary files still
return strings and are read again on each call. Encrypted files return
`SecretString` references backed by an immutable copy of the original ciphertext.
Later reads do not reopen the source file or keep its decoded contents.

The default opener uses standalone password input and the selected file-key
store described in [file encryption](file-encryption.md). It creates its
decryption context only for encrypted reads. Ordinary reads and runner
initialization do not request a password or open a store. It leaves
`builtins.open` unchanged. `await runner.finalize()` closes only its own default
opener and invalidates its references. Those references require `silent=True`
for trusted reads; they have no disclosure-confirmation handler.

`using_file_opener(None)` disables capture for directly created readers. A runner
initialized in that scope uses its default opener.

With the parser directly, set the context around the call as before:

```python
with using_file_opener(capture):
    tree = await config_loader.parse(config, config_path)
```

Lazy factories keep the same opener for readers they create later. The parser
does not clear or replace the caller's opener context. See
[resource cleanup](config-resource-ownership.md) for closing the created objects.

## Async input and cancellation

An async opener runs in the task that calls the reader. A normal opener runs in
a worker thread. If a normal opener returns an awaitable, the reader awaits it
in the calling task.

Concurrent reads share one successful capture. Failed or cancelled async
capture can be retried. Cancelling a wait for a normal opener lets its worker
finish and keep the captured reference. A failed protected read does not fall
back to reading the source as plain text.

An opener may run long after config loading. Check current access and request
any required private input when it runs, rather than saving a password or session
number when creating the config tree.

Custom openers normally return `ISecretRef[bytes]`. An opener that also supports
ordinary reads can return `w3plex.security.file_opener.PlainFile(raw_bytes)` for
that case. These bytes are decoded as ordinary text and are not cached. Returning
raw bytes directly is refused, and a failed encrypted read never falls back to
ordinary reading.
