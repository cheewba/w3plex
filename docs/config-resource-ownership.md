# Resource cleanup

Config factories can create objects that need closing, such as connections,
files and generators. The config parser tracks these resources as it creates
them.

## Let the tree manage cleanup

By default:

- If parsing fails, the parser closes the objects it has already created.
- If parsing succeeds, `await tree.close()` closes them.
- With `Runner`, use `await runner.finalize()` to close the tree and its log outputs.

Resources close in reverse order. When several config entries refer to the same
object, that object is registered for cleanup once.

## Manage cleanup in the caller

Pass `resource_owner` when your application needs to control when cleanup runs.
This is useful when construction fails before a tree can be returned, or when
your application needs its own cancellation handling.

```python
from contextlib import AsyncExitStack
from w3plex.runner import Runner

async with AsyncExitStack() as resources:
    runner = Runner()
    resources.push_async_callback(runner.finalize)
    await runner.init(config, "w3plex.yaml", resource_owner=resources)
    # Use runner.tree here.
```

The parser adds resources to this stack even if a later factory fails. The
`async with` block closes them before finalizing the runner.

`config_loader.parse(..., resource_owner=resources)` uses the same rule. With an
external owner, closing the tree does not close those resources. The caller must
close its stack after success, failure or cancellation, and must also finalize
its runner.
