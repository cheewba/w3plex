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

## Existing YAML and external-file readers

Keep the existing configuration format. YAML selects constructors and their
parameters; sensitive data can live in separate ordinary or ENC1 files:

```yaml
accounts:
  main:
    __init__: w3plex.utils.loader:accounts_loader
    file: keys.enc
```

The trusted host enables protected reading on the existing Runner:

```python
from functools import partial
from w3plex.config import load_config
from w3plex.runner import Runner

# The host supplies an unlocked store and a LegacyContext with private input.
config = load_config("w3plex.yaml", opener=legacy.open, environment={})
runner = Runner()
await runner.init(
    config,
    "w3plex.yaml",
    file_opener=partial(store.capture_file, legacy=legacy),
)
accounts = await runner.tree.accounts.main()
```

The same option is available on `config_loader.parse(config, filename,
file_opener=...)`. The opener belongs to trusted code and must approve source
access before capture. It returns a local byte reference or raises a safe error.
Protected failures never retry through ordinary reading. Imports alone do not
enable this mode.

YAML class names, file paths, `$...` references, lazy factories and include
source directories keep their existing meaning. The existing FileLoader binds
the opener during construction, including deferred factories. Concurrent
runners keep separate bindings. Readers created during an application call use
that Runner's opener as well.

The reader captures its source on first read and reuses that reference after
lock/unlock, even if the file changes or disappears. Concurrent first reads
capture once. Create a new reader or explicitly capture a new source to use
changed data. This mode also protects plaintext input in the vault; it does not
rewrite the original input file. The host owns the vault and legacy context and
must lock both when their session ends or locks.

The existing accounts loader creates `w3plex.w3.Account` for referenced keys.
The account retains a reference and a public address; `.key` returns that
reference. It creates signing dependencies only during use. Ordinary mode keeps
its existing w3ext account type and key access. Signing authorization and
transaction approvals remain the service's responsibility.

The public-address loader validates values privately and returns ordinary
checksummed address strings. Generic protected transforms receive references;
unsupported consumers do not trigger automatic plaintext conversion. Use
`FileLoader(file=reference)` for already captured data. The earlier
`FileLoader.from_secret(...)` and `SecretFileLoader(...)` entry points use the
same reader implementation. Ordinary readers still return strings and reopen
the file on each call. BOM, whitespace, comments and filtering stay compatible.

## Optional encrypted YAML

`load_config` can read encrypted YAML using `legacy.open`, as it can read
ordinary YAML. `load_reference_config` reads an already captured YAML source
and explicitly preloaded includes. It keeps ordinary configuration values and
include metadata so the result can go through the existing tree parser.
It performs no implicit include-file reads and does not convert YAML to JSON or
wrap class names, paths and object references in SecretJson. This corrects the
initial unreleased helper's string-wrapping behavior.

Parsed configuration is trusted private data. Inline values are ordinary Python
values; keep sensitive values in protected external files. YAML parsing and
variable expansion can create temporary plaintext copies.

## Structured external data and credentials

```python
from w3plex.security import SecretJson
from w3plex.security.contracts import SecretKind

source = store.capture_file("credentials.json.enc", legacy=legacy)
api_key = SecretJson[str](source, ("debank", "api_key"))
credential = store.credential(api_key, kind=SecretKind.API)
```

JSON paths handle escaping. String offsets count bytes in the parent's decoded
bytes or encoded text and must not split a codepoint. Immutable local handles
survive configuration deepcopy by identity while still refusing serialization.

`store.credential` copies a selected value into a classified encrypted API,
RPC or model record without returning plaintext to the caller. Alternatively,
use `store.capture(value, kind=SecretKind.API)` for private imported bytes.
Registered `ProtectedHTTP`, `ProtectedDeBank`, `ProtectedOdos` and `ProtectedRPC`
in `w3plex.w3` accept these local references or the existing ID DTOs. They retain
destination checks, request authorization and Session.use guards. Authorizers
receive ID DTOs only; local selection fingerprints bind the request digest.
Unclassified references and references owned by another vault are refused.
Other public w3ext exports keep their original class identity.

## Current protection scope

Encrypted snapshots avoid long-lived plaintext fields. Native owned buffers
are cleared after use. Python parsers, Argon2id, signing and HTTP/TLS dependencies
can still create temporary immutable copies. This API does not prove removal
of every copy or protection from a privileged full-memory snapshot.

Current native/storage component checks cover macOS and selected Linux probes.
Native Windows protection is unavailable and fails closed. Full collector/dump
acceptance remains unfinished. Do not describe these library changes as a
completed Cryptopal CLI, proxy service or sandbox implementation.
