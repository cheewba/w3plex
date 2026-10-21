# Optional async file capture

Trusted hosts can pass `async_file_opener` to `Runner.init` or
`config_loader.parse`. The callback accepts a file path and returns an
`ISecretRef[bytes]` through an awaitable. The existing parser constructs the
same readers and retains this callback for later Lazy factories and Runner
application calls.

```python
async def capture(path):
    # Check the current admitted operation here, including after private input.
    # Return a protected immutable snapshot through a local reference.
    return await trusted_capture(path)

await runner.init(config, config_path, async_file_opener=capture)
```

`FileLoader(file=path, async_opener=capture)` selects the callback for one
reader. `using_async_file_opener(capture)` supplies a contextual default;
`get_async_file_opener()` reads it. An explicit `async_opener=None` disables
that default for the reader. These APIs live in `w3plex.utils.loader`.

An existing reference supplied as `file` takes precedence over either opener.
Otherwise an async opener takes precedence over the synchronous `opener`.
Without an async opener the existing synchronous/threaded and ordinary file
read paths keep their behavior. Setting `async_opener=None` allows a reader's
synchronous opener or ordinary read path to run even under an async default.

The async callback runs directly in the task awaiting the reader. A per-reader
asyncio lock serializes first capture on that event loop. A successful capture
is retained once; failed or cancelled capture leaves the reader available for
retry. Callback failures use the existing private-error sanitizer. Line filters,
transforms and SecretString byte offsets use the existing reader implementation.
`accounts_loader` remains a deferred callable.

The callback can run long after initialization. Obtain current operation/session
authority when it runs; do not bind a session generation or password at tree
construction. The library does not implement private dialogs or operation policy.
The host owns those checks and any private input retry inside capture. Capture
success stores only the reference, and later reads resolve it normally. A store
can therefore deny reads while locked and restore them after unlock without
rereading the original file. Existing resource ownership rules still apply; see
[config resource ownership](config-resource-ownership.md).
