# Secret references

`w3plex.security` protects data: encryption, storage, native owned buffers,
lock state and secret references. `w3plex.w3` contains consumers such as signing,
registered HTTP, RPC and DeBank/Odos. Config and line readers live in their
normal namespaces. Old security consumer imports remain compatibility aliases.

The new API is opt-in. Existing `w3plex.secure`, ordinary file reads, ENC1/KS01
files and `w3ext.Account.from_key(string)` keep their behavior. Importing the
new API does not patch `open()`, unlock a store or change process protections.

## Local references and public IDs

`from w3plex.security import SecretRef` imports a local handle. It holds an
encrypted record's ID and an owner. It does not retain the plaintext value.
`SecretString` adds a byte range and encoding. `SecretJson` adds a field path.
Children can select values from decoded parents without caching those values.

The existing `w3plex.security.contracts.SecretRef` is an ID DTO for service
boundaries. It contains only an ID, kind and optional public address. It has no
retrieval method. Do not serialize a local handle or expose its owner to an
agent. Local handles reject pickle and ordinary JSON serialization.

## Capture once and restore after unlock

Create a `SecretStore` using an explicitly protected, unlocked `Vault`:

```python
from w3plex.security import SecretJson, SecretStore, SecretString
from w3plex.w3 import Account

store = SecretStore(vault, confirm=confirm_export, authorize=check_access)
source = store.capture(b'{"wallet":{"key":"' + b"01" * 32 + b'"}}')
key = SecretJson[str](source, ("wallet", "key"))
account = Account.from_key(key)
signature = await account.sign("public test message")
```

The key above is public test data. Never fund its wallet.
The host supplies `vault`, trusted confirmation and access callbacks.
It explicitly activates `ProcessProtection` before secret input or unlock.
Real service applications use `Session` for private unlock and idle locking.

`store.capture_file(path, legacy=context)` privately captures an ordinary or
ENC1 source. Pass an explicit `LegacyContext` for encrypted legacy input.
Original files are not rewritten. Captured values are encrypted in the vault
before a handle is returned. Changing or deleting the source cannot change a
reference's value. Capturing again creates a new record ID.

`vault.lock()` clears owned unlock material. Handles keep their immutable
metadata. They work again after the same vault unlocks. To reopen after a
restart, construct a fresh `CiphertextFile` and `Vault`, unlock it, and use
`store.reference(saved_identifier)`. Reconstruct child ranges/paths from trusted
metadata. For classified credentials, also pass their saved `kind`.

Data snapshots are bounded to 1 MiB each and the existing vault is bounded to
8 MiB overall. Existing credential record limits remain 64 KiB. Required native
allocation and memory locking must succeed; larger supported data does not
authorize a weaker memory profile.

## Deliberate plaintext export

```python
value = key.ref()             # trusted confirmation is required
value = key.ref(silent=True)  # deliberately suppress that confirmation
```

`ref` is a named method, not `__call__`. `silent` defaults to False and is a
keyword-only bool. Confirmation receives a `SecretAccess` with the record ID,
action and selection fingerprint. It never receives the value being disclosed.
Return exactly True to approve. Missing interaction returns
`InteractionRequired`; refusal returns `PermissionDenied`.

`silent` skips only the warning. It cannot skip host access checks or unlock.
Lock/reunlock and access revocation during confirmation invalidate the attempt.
A final child disclosure asks once; parent restoration adds no extra prompts.
Already exported bytes, strings or containers cannot be revoked by later lock.

The `authorize` callback checks `AccessKind.USE` or `AccessKind.DISCLOSE`. An
optional `check` callback adds host session checks. Without these callbacks,
this is a trusted standalone interface. Python code in the same process is
trusted; attribute hiding and the warning are not an intra-process boundary.
Cryptopal must check permissions in its service and expose restricted proxies
whose schemas include neither local handles nor the `silent` option.

## Readers and credentials

```python
from w3plex.config import load_reference_config
from w3plex.utils.loader import FileLoader
from w3plex.security.contracts import SecretKind

keys = await FileLoader.from_secret(key_file_reference).process()
accounts = [Account.from_key(key) for key in keys]

config = load_reference_config(
    config_reference,
    environment={},
    includes={"debank.yaml": debank_reference},
)
credential = store.credential(config.debank.api_key, kind=SecretKind.API)
```

The protected line reader keeps UTF-8 BOM, comments, whitespace and filter
behavior. Transforms receive references. The ordinary FileLoader still returns
ordinary strings. JSON paths handle escaping; string offsets count bytes in
the parent's decoded bytes or encoded text and must not split a codepoint.

The config reader uses only preloaded include references. It performs no
implicit source-file reads. It encrypts the parsed, expanded configuration as a
new snapshot and replaces string values with `SecretJson` handles. The whole
configuration remains private service data; numbers, booleans and field names
are not a safe model export format by themselves.

`store.credential` copies a selected value into a classified encrypted API,
RPC or model record without returning plaintext to the caller. Alternatively,
use `store.capture(value, kind=SecretKind.API)` for private imported bytes.
Registered `ProtectedHTTP`, `ProtectedDeBank`, `ProtectedOdos` and `ProtectedRPC`
in `w3plex.w3` accept these local references or the existing ID DTOs. They retain
destination checks, request authorization and Session.use guards. Authorizers
receive ID DTOs only; local selection fingerprints bind the request digest.
Unclassified references and references owned by another vault are refused.

`w3plex.w3.Account` retains a reference and a public address for protected keys.
It constructs a LocalAccount only during signing. Its `.key` returns the
reference. Ordinary string keys keep legacy behavior. Other public w3ext
exports keep their original class identity. Signing authorization, transaction
approvals and provider selection remain the consumer/service's responsibility.

## Current protection scope

Encrypted snapshots avoid long-lived plaintext fields. Native owned buffers
are cleared after use. Python parsers, Argon2id, signing and HTTP/TLS dependencies
can still create temporary immutable copies. This API does not prove removal
of every copy or protection from a privileged full-memory snapshot.

Current native/storage component checks cover macOS and selected Linux probes.
Native Windows protection is unavailable and fails closed. Full collector/dump
acceptance remains unfinished. Do not describe these library changes as a
completed Cryptopal CLI, proxy service or sandbox implementation.
