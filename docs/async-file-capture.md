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

With a runner, pass the opener to `init()`:

```python
await runner.init(config, config_path, file_opener=capture)
```

With the parser directly, set the context around the call:

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
