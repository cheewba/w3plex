# Protected integrations

Use these objects inside the trusted service. Give model callers typed operations
and public results, never the adapter, HTTP registry, Chain or provider object.
The host supplies an unlocked session, vault and request authorizer to
`ProtectedHTTP`. A secret reference identifies a record; it does not authorize use.

## DeBank

`ProtectedDeBank(http, credential, registration="debank")` registers the DeBank
OpenAPI `GET /v1/user/all_token_list` endpoint. `credential` must be an API-key
reference with HTTP use allowed. The adapter passes only a validated EVM address
and `is_all=true`. The HTTP module injects `AccessKey` for that request.

`await adapter.balances(address, operation="balances")` returns `TokenBalance`
records. Balances use exact integer `raw_amount`; prices use decimal strings.
Missing names, symbols and decimals remain `None`. Unregistered response fields,
headers and authentication never appear in these records. Invalid or echoed
secret fields cause a safe failure.

## Odos

`ProtectedOdos(http, registration="odos", chain_id=10)` uses the quote-v2 and
assemble paths from the existing w3plex integration. A trusted host may choose
another approved origin and an API-key reference with a defined authentication
header. The defaults do not claim that the public API requires that header.

Pass a tuple of `TokenInput(token, amount)` and a tuple of
`TokenOutput(token, proportion_bps)` to `quote(address, inputs, outputs,
operation=...)`. Amounts are integer token units. Output proportions must total
10,000 basis points; 5,000 means 50%. The default slippage is 50 basis points,
or 0.5%. The quote must report the same input tokens/amounts and output tokens.
Server reordering does not change the requested token order.

`assemble(quote, operation=...)` accepts only a quote issued by that adapter,
with its original owner, chain, inputs, outputs, path and slippage. It validates
the transaction's sender and chain when present, and returns a public
`SwapTransaction`. It does not approve tokens, sign or send. The signing layer
must authorize every required token approval and the final swap separately.
Call `discard_quote(identifier)` when preparation is no longer needed. Each
adapter retains at most 128 public quotes.

## Explicit RPC

Construct `ProtectedRPC(http, registration=..., operation=..., chain_id=...,
origin=..., path=..., credential=...)`. RPC credentials use `SecretKind.RPC` and
must allow HTTP use. Header, query, path and HMAC authentication follow the host's
registered request definition. No raw credential is passed to Web3 or a w3ext
provider pool.

Use an explicit provider and stop inherited routers for the whole operation:

```python
from w3ext import Chain, chain_providers_router

chain = Chain(10)
with chain_providers_router(None):
    await chain.connect_rpc(protected_provider)
    balance = await chain.eth.get_balance(public_address)
    # Keep preparation/signing/submission inside this scope as well.
await chain.close()
```

An explicit provider alone does not override a forced legacy router. The `None`
scope prevents default Chainlist and outer routers from selecting another route.
Concurrent tasks can use their own protected provider and operation ID.

The adapter accepts chain/block reads, balances, code, transaction counts, gas
estimation and fees, contract calls, hash/receipt lookup and raw transaction
submission. Transaction defaults and signing remain in `LocalSigning`. Each RPC
method is fixed in its HTTP registration; callers cannot replace it with a
signing or administration method. Only defined argument fields are accepted.
Full block transactions, batches, subscriptions, provider-side signing and
CCIP-read HTTP callbacks are refused. Receipts and transactions may be `None`
until the network knows them.

Each request checks authorization, session and destination through protected
HTTP. Requests use no Web3 HTTP session manager or credential-valued cache key.
`disconnect()` cancels this provider's active work and prevents future reuse.
Session lock closes credential connections and rejects later credential use.
Closing a request does not prove erasure of immutable Python or native TLS
copies; process and dump protections apply to those temporary copies.

Legacy DeBank, Odos, account APIs, HTTP pools and routing remain available with
their original arguments and behavior.
