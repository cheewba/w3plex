# Protected session ownership

Create one `Session` for a vault inside the trusted host. Session construction
locks any existing vault unlock material. A second live Session for that vault
is refused so two independent permission generations cannot share its key.
Standalone Vault use without a Session stays available to trusted programs.

Run Session-owned vault operations on the host event loop. Unlock through
`await session.unlock(operation)`, with the private input interface. Reusing an
active session needs no new password. Unlocking does not authorize an operation;
the signer, HTTP module and file exporter still check their own permissions.

Use `session.use(generation, operation, consumer)` for admitted, synchronous,
bounded secret work. It checks the current generation and monotonic idle deadline
immediately before the consumer runs. The first successful secret use of an
operation refreshes activity. Polls, denied requests and stream chunks do not.
Asynchronous work must recheck the generation after waiting and before secret use.

Use `await session.lock()` for user lock, inactivity, suspend/resume and shutdown.
Vault lock notification also revokes the session immediately after a direct vault
lock, password change or failed write. The notification holds only a weak method
reference; it does not keep the Session alive or expose unlock material.

Lock invalidates the generation first, cancels private input and active work, and
clears the vault key. It closes registered credential resources before waiting
for cancelled workers, since a network worker may need its connection closed to
finish. Queued HTTP authorization and DNS work is tracked too. Nested resource
tracking keeps the parent operation registered until its own work is finished.

Old replies, signing permits and credential requests cannot use the revoked
generation. A fresh private unlock is required after lock. Password changes or
failed atomic writes do not leave the Session reporting an unlocked vault.
Use `await session.close()` to finish cleanup and release storage ownership.

Lock cannot undo a request or transaction already sent. Its public result must
keep that uncertainty and the original transaction hash. Connection closure and
owned-buffer clearing also do not prove erasure of immutable Python or native
dependency copies; the host's declared process and dump protections must cover
those copies.
