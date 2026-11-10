# File capture with sync or async callbacks

Trusted hosts can pass `file_opener` to `Runner.init`. Direct callers of
`config_loader.parse` supply the opener through `using_file_opener` instead
of a parser argument. The callback accepts a file path and returns an
`ISecretRef[bytes]` directly or through an awaitable. The parser constructs the
same readers and retains this callback for later Lazy factories and Runner
application calls.

```python
async def capture(path):
    # Check the current admitted operation here, including after private input.
    # Return a protected immutable snapshot through a local reference.
    return await trusted_capture(path)

await runner.init(config, config_path, file_opener=capture)
```

Readers obtain their callbacks from context when constructed. For standalone
use, create the reader inside `using_file_opener(capture)`:

```python
from w3plex.utils.loader import FileLoader, using_file_opener

with using_file_opener(capture):
    reader = FileLoader(file=path)

values = await reader()
```

The same context supplies readers and lazy factories created by the parser:

```python
with using_file_opener(capture):
    tree = await config_loader.parse(config, config_path)
```

Parsing preserves the caller's opener context, including on failure or
cancellation. `Runner.init` establishes and restores this context itself.

The reader retains the callback after leaving the context.
`get_file_opener()` reads the current callback. These APIs live in
`w3plex.utils.loader`. Reader configuration contains only `file` and `filter`;
select the opener through `using_file_opener`. The separate `AsyncFileOpener`,
async context accessors and `async_file_opener` host argument have been removed;
use `FileOpener`, the shared context and `file_opener` for both callback kinds.

An existing reference supplied as `file` takes precedence over the opener.
Without an opener, ordinary file reads keep their behavior. Constructing a
reader inside `using_file_opener(None)` disables capture for that reader.
Nested contexts restore the previous callback when they exit.

Async functions and objects with an async `__call__` run directly in the task
awaiting the reader. Synchronous callbacks run in a worker thread. If a
synchronous callback returns an awaitable, the reader awaits it in the invoking
task. A per-reader asyncio lock serializes first capture on that event loop.
A successful capture is retained once. Failed or cancelled async capture can
be retried; cancelling a synchronous reader's wait lets its worker finish and
retain the snapshot. Callback failures use the existing private-error sanitizer.
Line filters, transforms and SecretString byte offsets use the existing reader implementation.
`accounts_loader` remains a deferred callable.

The callback can run long after initialization. Obtain current operation/session
authority when it runs; do not bind a session generation or password at tree
construction. The library does not implement private dialogs or operation policy.
The host owns those checks and any private input retry inside capture. Capture
success stores only the reference, and later reads resolve it normally. A store
can therefore deny reads while locked and restore them after unlock without
rereading the original file. Existing resource ownership rules still apply; see
[config resource ownership](config-resource-ownership.md).
