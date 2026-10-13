# Protected data and reference-aware consumers

`w3plex.security` protects arbitrary data. It provides encrypted storage, native
owned buffers, immutable snapshots and local references. Application permissions,
agent sessions, private dialogs and RPC contracts belong to Cryptopal.

## One reference protocol

```python
from typing import Protocol, runtime_checkable

@runtime_checkable
class ISecretRef[T](Protocol):
    def ref(self, *, silent: bool = False) -> T: ...
```

Consumers accept this protocol, including independent implementations. Runtime
`isinstance(value, ISecretRef)` checks members, not signatures, return types or
trusted provenance. An implementation is responsible for its own protection.
There is no `use()` API or shared concrete reference base.

Stored references return bytes. `SecretString` holds a parent, a byte offset,
length and encoding. `SecretJson[T]` holds a parent and a JSON path. Both live in
`w3plex.security.adapters` and are also exported by `w3plex.security`. They keep
extraction metadata, never decoded values. Nested adapters forward the disclosure
warning to the source once. The callback receives only the snapshot identifier.

The old local `SecretRef` type name aliases `ISecretRef`; the former adapter
imports from `w3plex.security.refs` remain compatible. Wallet/credential ID DTOs
are separate application types in `cryptopal.runtime.contracts`.

## Capture once and resolve when needed

The trusted host supplies a password and a confirmation handler. It explicitly
activates process protection before creating or unlocking a store:

```python
from pathlib import Path
from w3plex.security import SecretJson, SecretStore, SecretString
from w3plex.security.memory import ProcessProtection
from w3plex.security.storage import CiphertextFile
from w3plex.security.vault import Vault

protection = ProcessProtection()
protection.activate()
directory = Path.cwd() / ".secrets"
directory.mkdir(mode=0o700, exist_ok=True)
vault = Vault(CiphertextFile(directory / "vault"), protection=protection)
# First setup only; create refuses to overwrite an existing store.
vault.create(master_password)
vault.unlock(master_password)
store = SecretStore(vault, confirm=confirm_disclosure)
source = store.capture_file("credentials.json")
key = SecretJson[str](source, ("debank", "api_key"))
```

Capture encrypts and commits the input before returning a reference. It rejects
unsafe source links and changes during capture. Replacing or deleting the source
does not change an existing reference. A new capture has a new identifier.

`ref()` requests confirmation by default. Missing interaction, refusal or a
lock/reunlock during confirmation returns a fixed error without the value.
`ref(silent=True)` deliberately skips that warning; the store must still be
unlocked. w3plex has no application permission callback. Cryptopal checks its
own policy before calling a consumer and exposes neither local handles nor the
silent option to a model.

```python
value = key.ref()  # The caller receives ordinary plaintext after confirmation.
vault.lock()
vault.unlock(master_password)
assert key.ref(silent=True) == value
```

To reopen a snapshot, save its identifier and call `store.reference(identifier)`
after reopening/unlocking the same vault. Child adapters can be reconstructed
with their parent and fixed offset/path. Reopening does not read the source file.
Explicitly returned plaintext cannot be revoked by a later lock.

## Keep the existing YAML workflow

YAML still names constructors, parameters, paths and `$...` object references.
Protected values come from external data files, not from wrapping every YAML
string. For example, the existing account factory remains:

```yaml
accounts:
  main:
    __init__: w3plex.utils.loader:accounts_loader
    file: keys.enc
```

Enable protection on the existing Runner or config-tree parser:

```python
from functools import partial
from w3plex.config import load_config
from w3plex.runner import Runner
from w3plex.security.legacy import LegacyContext

legacy = LegacyContext("keystore.bin", input_handler=read_legacy_password)
cfg = load_config("w3plex.yaml", opener=legacy.open, environment={})
runner = Runner()
await runner.init(
    cfg, "w3plex.yaml",
    file_opener=partial(store.capture_file, legacy=legacy),
)
accounts = await runner.tree.accounts.main()
```

The host approves sources and handles private input. Readers capture the opener
when constructed; deferred factories and separate async runners keep their own
opener. An external file is captured on first read, once even with concurrent
reads. Locked/denied reads never fall back to ordinary plaintext. Plain readers
still reopen their file on each call. Includes preserve relative source paths.

`FileLoader(file=reference)` produces line references with the existing BOM,
comment, whitespace and filter rules. Account factories produce adapted accounts
for referenced keys and legacy accounts for plain strings. Address readers
validate privately and return public checksummed addresses. Generic transforms
must support references explicitly.

Optional encrypted YAML uses `load_reference_config` with approved captured
include sources. Constructor names, paths, `$...` references and include metadata
remain ordinary config values. The standalone CLI delegates to the same config
reader and supplies its legacy opener, environment and include encoding.
File encryption now lives in security; `secure.py` is removed in 0.1.0.
See [the migration guide](security-migration.md) for replacement imports and
explicit transparent-read activation.

## SDK objects retain references

```python
from w3plex.w3 import Account, Debank

account = Account.from_key(SecretString(store.capture_file("key.txt")))
debank = Debank(access_key=key)
```

Account keeps the reference and public address, without a retained plaintext key
or signing account. It resolves the reference with `ref(silent=True)` during use.
DeBank resolves its access key when constructing per-request headers. Odos also
accepts a reference for its referral field and works with the adapted Account.
Their ordinary string arguments retain existing behavior. Unchanged w3ext
classes remain re-exported by identity. Unsupported consumers require explicit
retrieval through `ref()` before passing a plain value.

These SDK objects have no agent permissions or destination policy. Cryptopal
owns guarded signing/HTTP/RPC, one-use approvals, inactivity and private input.
Its trusted registry classifies records and binds references to application ID
DTOs; the generic vault treats record metadata as opaque data.

## Compatibility and limits

Existing CLI entry points, transparent plain/ENC1 reads and KS01 stores remain.
New library imports do not enable encrypted `open()` or change process policy.
Legacy contexts require explicit activation. Original files are not rewritten;
old vault records remain readable by the generic storage engine. Experimental
policy modules moved to `cryptopal.runtime`; their old library aliases are gone.

Lock the vault and any legacy contexts on session end. The host controls idle
locking. Legacy caches contain Python key copies; locking them clears their
references but does not prove erasure of every dependency copy.

Captured values are bounded to 1 MiB and a vault envelope to 8 MiB. JSON paths
and nested adapters are bounded to avoid unbounded restoration. AEAD authenticates
the complete encrypted payload before any value is returned; a range does not
permit an unauthenticated seek into ciphertext.

Native owned buffers are cleared after use, but Python parsers, cryptography,
signing and HTTP/TLS dependencies create temporary copies. A reference protocol
or callback cannot prevent a trusted consumer from retaining plaintext. No
immunity to privileged full-memory snapshots or expiry of captured keys is
promised. Native Windows storage/memory controls and the full dump-collector
matrix still require implementation and verification. Import/type/unit checks
are not evidence of completed Cryptopal CLI, RPC or sandbox isolation.
