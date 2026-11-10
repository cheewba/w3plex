# Resource cleanup

Config factories can create objects that need closing, such as connections,
files and generators. Each owner closes its own children. The config tree owns
objects created by its factories; Runner owns that tree and its own log outputs
and default file opener.

## Let the tree manage cleanup

By default:

- If parsing fails, the incomplete tree closes the objects already created.
- If parsing succeeds, `await tree.close()` closes them.
- With `Runner`, use `await runner.finalize()` to close the tree and its log outputs.

Resources close in reverse order. When several config entries refer to the same
object, that object is registered for cleanup once.

Runner does not accept `resource_owner`. The application calls finalize() rather
than collecting the runner's resources in an external stack:

```python
from w3plex.runner import Runner

runner = Runner()
try:
    await runner.init(config, "w3plex.yaml")
    # Use runner.tree here.
finally:
    await runner.finalize()
```

Each tree and runner retains one cleanup task. Cancelling a caller waiting for
close() or finalize() does not cancel that cleanup. Await the method again to
join it. Runner waits for unfinished cleanup before another init(). A failed
close remains an error on later waits and prevents reinitialization; a repeated
call does not report success after a closer failed.

Factories must clean up resources allocated inside a constructor that fails
before returning an object. The tree cannot own an object it never received.

## Low-level parser compatibility

`config_loader.parse(..., resource_owner=resources)` remains available for direct
parser users. With that explicit external owner, closing the tree does not close
the supplied stack. The caller must close it after success, failure or
cancellation. Runner always uses tree-owned resources.
