# w3plex

Run asynchronous Web3 tasks across wallets and chains from a small YAML config.
w3plex combines [w3ext](https://github.com/cheewba/w3ext) for blockchain access
with [lazyplex](https://github.com/cheewba/lazyplex) for applications, actions,
and plugins.

The included balance application reads public wallet addresses and displays
native-token or ERC-20 balances. You can also write your own Python applications,
use the interactive shell, and share configured chains, clients, and proxies.

Version 0.1 moves file encryption to `w3plex.security` and removes `w3plex.secure`.
Existing encrypted files and CLI commands remain supported. Scripts must update
their imports and explicitly enable transparent reads; see
[the migration guide](docs/security-migration.md).

## Install

You need Python **3.12 or newer** and Git. CI currently checks Python 3.12.

```sh
git clone https://github.com/cheewba/w3plex.git
cd w3plex
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
w3plex --help
```

On Windows, activate with `.venv\Scripts\Activate.ps1`. Installation fetches
the pinned Git dependencies: w3ext **0.0.5** and lazyplex **0.0.4**.

## Your first balance check

Run these commands in the directory where you want to keep your configuration:

```sh
w3plex init
```

This creates three files:

| File | What to put in it |
| --- | --- |
| `w3plex.yaml` | Applications, action defaults, and the chains to load |
| `chains.yaml` | Chain settings and RPC URLs |
| `wallets.txt` | One public EVM address per line |

Existing files are preserved; initialization refuses to replace an existing
main config. To use another location, run `w3plex init --config project/w3plex.yaml`.

Set your Ethereum RPC URL in a `.env` file in your **working directory**:

```dotenv
ETH_RPC_URL=https://your-provider.example/your-api-key
```

If you are working in the repository, you can start with `cp .env.example .env`
and replace the example URL. Exported environment variables take precedence.

Add addresses to `wallets.txt`:

```text
# Public addresses only; blank lines and comments are ignored.
0x0000000000000000000000000000000000000001
```

Then run:

```sh
w3plex balance
# The same default action, named explicitly:
w3plex balance onchain
# Override the wallet list for this run:
w3plex balance onchain wallets=0x0000000000000000000000000000000000000001
```

Balance checks do not need private keys. The starter config selects Ethereum
and its native ETH balance. Each selected chain connects at startup, so only
include chains you have configured RPC access for.

## Choose chains and tokens

The main config selects entries from `chains.yaml`:

```yaml
chains: !include
  file: chains.yaml
  items: [ethereum, bnb_chain]
```

Set `ETH_RPC_URL` and `BNB_RPC_URL` in `.env` for that selection. The supplied
chain file also includes Optimism, Polygon, Arbitrum, and zkSync Era, each with
its own RPC environment variable.

In `applications.balance.actions.onchain`, list tokens as `chain:token`:

```yaml
onchain:
  tokens:
    - "ethereum:ETH"
    - "bnb_chain:BNB"
    - "bnb_chain:0x55d398326f99059ff775485246999027b3197955"
  threads: 2
  attempts: 2
```

A token can be the chain's native symbol, a configured token alias, or an ERC-20
contract address. You can preload aliases in the chain definition:

```yaml
ethereum:
  chain_id: 1
  currency: ETH
  rpc: ${ETH_RPC_URL}
  scan: https://etherscan.io/
  erc20:
    USDC: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
```

Use `ethereum:USDC` after adding that alias. `*:ETH` looks up ETH on every loaded
chain that exposes it. A token wildcard such as `ethereum:*` is not a token
discovery mechanism for onchain lookups.

`threads` limits simultaneous chain requests **per wallet**; wallet actions run
concurrently. Set it to `null` for no chain limit. `attempts` includes the first
request, and retries wait one second. Wallet failures appear alongside successful
results in the balance output.

## Commands and overrides

```sh
w3plex --config project/w3plex.yaml balance onchain
w3plex balance onchain --config project/w3plex.yaml
w3plex balance onchain threads=2 attempts=3
w3plex balance onchain 'tokens=["ethereum:ETH", "ethereum:USDC"]'
w3plex shell
```

Put positional arguments, including the action name, before `key=value`
arguments. Values use YAML types: `false` is a boolean, `2` is an integer, and
`[1, 2]` is a list. Quote the whole argument when it contains spaces or shell
wildcards. CLI values override application and action defaults.

`w3plex --help` lists available applications from the selected config.
`w3plex balance --help` shows the application's command syntax.

## DeBank balances, NFTs, and DeFi positions

The `debank` action adds USD estimates. For the documented DeBank OpenAPI,
add an access key to `.env`:

```dotenv
DEBANK_ACCESS_KEY=your-access-key
```

Then add this field under `applications.balance.actions.debank`:

```yaml
debank:
  access_key: ${DEBANK_ACCESS_KEY}
  filter:
    - "*:ETH > 0.01"
    - "bnb_chain:* >= $1"
```

```sh
w3plex balance debank
w3plex balance debank total=true 'filter=[]'
```

Filters are joined with OR. Each filter has the form `chain:token` followed by
an optional comparison (`>`, `>=`, `<`, `<=`, `==`, or `!=`). Chains accept names,
numeric IDs, or `*`; tokens accept symbols, names, addresses, or `*`. A `$` before
the threshold compares the estimated USD value. The filter language accepts
numeric comparisons only.

Without `access_key`, balance requests use the existing DeBank website endpoints;
those can reject requests or change independently of this package. The starter
`debank-total` alias uses that path with `cache_only: true`. With an OpenAPI key,
balances always use the token-list endpoint and `cache_only` has no effect.
You can use `chains: {}` for a DeBank-only config to avoid RPC connections;
chain-name filters then use DeBank IDs such as `eth` and `bsc`, or use numeric IDs.

Python callers can also retrieve NFT records and DeFi positions:

```python
from w3plex.modules.debank import Debank

async def portfolio(address, access_key):
    async with Debank(access_key=access_key) as client:
        balances = await client.get_balance(address)
        nfts = await client.get_nft(address)
        projects = await client.get_projects(address)
        return balances, nfts, projects
```

NFT and project methods require an OpenAPI access key and return the API's JSON
records. See the [official DeBank API reference](https://docs.cloud.debank.com/en/readme/api-pro-reference/user)
for key setup and response fields.

## Write a small application

Create `hello.py` beside your config:

```python
from w3plex import application

@application
async def hello(action, names=None, **config):
    results = yield names or ["world"]
    for result in results:
        print(result)

@hello.action("greet", default=True)
async def greet(name, greeting="Hello", **config):
    return f"{greeting}, {name}!"
```

Add the application to `w3plex.yaml` (or use this as a complete, offline config):

```yaml
applications:
  hello:
    __init__: hello:hello
    names: [Alice, Bob]
    actions:
      friendly:
        action: greet
        greeting: Good morning
```

```sh
w3plex hello
w3plex hello friendly 'greeting=Hi there'
```

The application yields items; its action runs once for each item, and the
application receives the collected results. Action aliases such as `friendly`
can select a Python action and supply defaults. Add `return_exceptions=True` to
`@application(...)` if you want errors returned in the results for individual items.

Use `from w3plex import logger` for context-aware logging, and
`from w3plex.utils import get_chains, get_config` to access the current
application's chains and configuration.

## Share objects through configuration

An `__init__: package.module:callable` mapping constructs an object with the
remaining fields as keyword arguments. The initializer can be a class, a
function, or an async function. References such as `$chains.ethereum` reuse
resolved objects, including forward references and references inside lists.
Circular references produce a configuration error.

```yaml
proxies:
  __init__: w3plex.modules.proxy:ProxyPool
  proxies: proxies.txt

applications:
  balance:
    __init__: w3plex.apps.balance:balance
    wallets:
      __init__: w3plex.utils.loader:wallets_loader
      file: wallets.txt
    actions:
      debank:
        proxy: $proxies
        filter: ["*:*"]
```

`ProxyPool` reads one proxy URL per line and leases proxies with
`async with pool.get_proxy()`. Blank lines and comments are ignored. HTTP and
SOCKS proxies are supported by the DeBank client; `socks5h://` enables remote DNS.
The old `w3plex.services.proxy.ProxyService` name remains available but is deprecated.

Other configuration features:

| Syntax | Behavior |
| --- | --- |
| `!include path.yaml` | Include YAML relative to the containing file; nested includes work |
| `!include {file: path.yaml, items: [name]}` | Include selected mapping entries |
| `${ENV_NAME}` | Expand environment variables while loading YAML |
| `__var__: true` | Make an object available through `$.vars.<name>` |
| `$.context.item` | Resolve the current action's item when the action runs |
| `__lazy__: true` | Pass a lazy object to the application/action for explicit `await object()` |
| `__factory__: true` | Pass a lazy factory; each explicit call constructs a fresh object |

Context-dependent objects resolve on demand and cache per action. Explicit lazy
objects called in application scope cache there. Relative file paths are resolved
against their config or included file when the file exists. Import paths use
`package.module:attribute`; local Python modules must be importable from your
working directory or installed on your Python path.

Runner cleanup closes configured objects with a `close()` method. A generator
initializer can yield a resource and release it in `finally`; both sync and async
generators are supported. Cleanup also runs if initialization or execution fails.

## Shell and dashboards

`w3plex shell` opens a Python REPL with `apps`, `chains`, `cfg` (raw config), and
`root` (resolved objects). For example:

```python
await apps.balance("onchain", threads=2)
chains.ethereum
```

The shell also awaits returned application coroutines automatically. Ctrl+C
cancels active work while keeping the shell available.

Custom applications can show live Rich panels:

```python
from w3plex.plugins import dashboard_page

async def show_status():
    async with dashboard_page("Status") as page:
        page.register_panel("Work", [("Completed", "{completed}")])
        page.set_variable_provider(lambda: {"completed": 3})
        # Await your work here while the page is open.
```

Use left/right (or `h`/`l`) to change pages and up/down (or `k`/`j`) to navigate
nested pages. `q` requests a quit; long-running application code can observe the
dashboard manager's `quit_requested` flag. Dashboard log capture is active while
the display runs. The balance application uses the progress-bar plugin.

## Encrypt local files

Encryption commands work without an application config:

```sh
# Prompt for a file password and create wallets.txt.enc:
w3plex encrypt wallets.txt
# Also remember the file key in the encrypted keystore:
w3plex encrypt wallets.txt --add
# Decrypt to a chosen destination:
w3plex decrypt wallets.txt.enc --output restored-wallets.txt
# Try a key from the keystore:
w3plex decrypt wallets.txt.enc --keystore --output restored-wallets.txt
```

`--overwrite` replaces the source in place. Without an output path, encryption
adds `.enc` and decryption replaces the final suffix with `.dec`. Glob patterns
and multiple sources are supported; `--output` accepts exactly one source.

When the CLI reads an encrypted config or input file, it decrypts it in memory
and prompts as needed. One file-key store serves both ENC1 and W3FILE1 files.
Its default path is `~/.keystore.bin`, selected by `W3PLEX_KEYSTORE`.
`W3PLEX_SECRET_STORE` is an optional alias for an explicitly selected path.
If both variables are set, they must select the same path. Master passwords
are separate from file passwords and are never written to disk.
Transparent reads allow three password attempts and report the remaining
count after each incorrect master or file password. Cancelling stops the read.

Unlocking an old KS01 store automatically upgrades it in place. The usual
private master-password prompt is the only interaction: the same password
protects the new vault. No migration command or extra confirmation is needed.
Before atomic replacement, an exact encrypted copy is saved at
`<keystore>.legacy.bak`. A plaintext legacy store needs a new master password
and confirmation because it had no password; its backup is encrypted W3FILE1.
No plaintext key copies or passwords are written to temporary files.

Existing encrypted external files stay unchanged. After migration one unlock
serves both formats, and the current context stays unlocked. Merely creating a
context or reading a plain file does not upgrade the store. Explicit legacy
source contexts keep their original import/interoperability behavior. Old
w3plex readers can use the KS01 backup because they cannot read the modern vault.
Wrong passwords and cancelled input leave the source intact. An unrelated
backup is never overwritten. Keep it safe and move it out of the backup path
before retrying. Interrupted migration is retryable; unlocking a modern store
does not migrate or rewrite it. Missing stores are created in modern format.

New encryption writes W3FILE1 with Argon2id and AES-256-GCM. The reader still
accepts ENC1 files and KS01 keystores. A LegacyContext writer can produce old
files when an old reader needs them. Existing encrypted inputs are not rewritten.

w3plex does not enforce filesystem owner, access modes or ACL policy. Existing
accessible directories work without chmod; applications can enforce their own
policy through the storage backend. Atomic writes, bounded reads, identity
checks and rejection of unsafe links remain active. Newly created files use
conservative access modes, and plaintext is never written to temporary files.
The experimental CiphertextFile(private=...) parameter has been removed.

Use password prompts instead of putting passwords in shell history. Keep
plaintext outputs, secret stores and credentials out of version control.

## Other modules

`w3plex.modules.odos.Odos` provides quotes, transaction assembly, token approvals,
and swaps using an account and a chain. Use it as an async context manager or
call `await client.close()` to release its HTTP session. Calling `swap()` submits
transactions; quote retrieval does not. It is a Python integration, with no
built-in swap CLI application.

`TokenLookup`, `ContractLookup`, and `ContractMethodLookup` in `w3plex.utils.filter`
resolve `chain:token`, `chain:address`, and `chain:address:method` templates against
loaded chains. Contract methods need an ABI or a w3ext function signature before
they can be called.

## Development

The GitHub Actions workflow runs Ruff, Pyright, compilation, an import smoke
check, and the regression tests. To run the same checks locally, activate `.venv`
and install the pinned check tools (Node.js is needed for Pyright):

```sh
python -m pip install ruff==0.16.8 pytest==9.0.2
npm install --global pyright@1.1.408
ruff check src tests
ruff format --check src tests
pyright
python -m compileall -q src
python -c "import w3plex"
pytest -q
```

Tests use mocked blockchain/API responses and temporary files; they do not need
RPC credentials or submit transactions. Live provider access and third-party
API behavior need separate checks with your own configuration.

## Troubleshooting

| What you see | What to check |
| --- | --- |
| A message asking you to set an RPC variable | Put the selected chain's URL in your working directory's `.env`, or export it |
| Connection or chain-ID errors | Check the RPC URL, credentials, and whether it serves the configured network |
| An application is missing from help | Check `--config`, `applications`, and the `__init__` import path |
| `wallets.txt` is missing or an address is invalid | Check the file path and use one public EVM address per line |
| A token has no balance entry | Check the selected chain, symbol/alias, and contract address |
| DeBank rejects a website request | Configure an OpenAPI access key for the `debank` action |
| An empty proxy file error | Add at least one proxy URL, or remove the action's proxy setting |
| Wrong file or master password | Use the matching password; master and file passwords serve different roles |
