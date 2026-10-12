# Protected local signing

`w3plex.security.signing.LocalSigning` runs inside the trusted host service.
Callers identify a vault wallet with a `SecretRef`; they do not supply its key.
Importing the module does not activate process protection or unlock the vault.

The host supplies a session, an async authorizer and a journal. Unlocking a
session does not approve signing. A missing authorizer or plan mode prevents
both signing and sending.

For a transaction, the adapter uses the existing `w3ext.Chain` and default-fill
functions to finish chain ID, nonce, gas and fees. It then awaits authorization
of that exact immutable request, signs locally and sends only signed bytes.
The wallet key is never installed in w3ext middleware or given to an RPC provider.

No w3ext signing hook is needed for this path. Existing account objects, `.key`,
synchronous signing and automatic signing middleware keep their behavior for
trusted legacy programs. Protected callers use the separate adapter explicitly.
They must not register a legacy account on its RPC chain.

Fee defaults use the existing AsyncWeb3 helper for the current RPC context.
They do not reuse the fee-model cache on a shared Chain. Submission also checks
that the destination Chain matches the chain ID authorized in the transaction.

An authorization is tied to one request and unlocked session. It expires and
can be used only once. Changed transaction fields or message data need another
authorization. The host decides whether user confirmation or an admitted policy
permits the exact request.

Personal signing accepts UTF-8 text or literal bytes. EIP-712 accepts a mapping
with the domain, types and message. Protected signing does not infer EIP-712
from a JSON string or infer binary data from a text beginning with `0x`.
Existing legacy message APIs retain their conventions.

`SignedTransaction` is private host state. It must not be returned through agent
RPC or included in routine logs. Before broadcast, `Journal.commit` must return
exactly `True` after durable storage of the operation, request identity and hash.
The host must keep signed bytes in restricted encrypted storage. An in-memory
journal is suitable only for tests.

If broadcast has an unknown result, the public result keeps the same transaction
hash and uncertain state. It does not sign a replacement. The application owns
durable journal storage and the recovery UI.

These interfaces are host library ports. They do not authenticate RPC clients,
isolate agent code or implement a chat application. The host must enforce those
boundaries and establish its process protection before accepting secrets.
