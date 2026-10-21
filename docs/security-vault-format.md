# Vault format V1

This is a new format for the trusted security runtime. Old `ENC1` and `KS01`
files keep their existing readers. Import preserves those source files.

A file starts with `W3VAULT1` and a newline, followed by a JSON object with exactly
three fields: `header`, `wrapped_key` and `payload`. Binary values use standard
Base64. The maximum file size is 8 MiB and the maximum canonical header size is
4 KiB. Unknown versions, duplicate fields and non-finite JSON numbers are rejected.

The header contains:

| Field | Required value |
| --- | --- |
| `version` | Integer `1` |
| `cipher` | `AES-256-GCM` |
| `context` | `w3plex.vault` |
| `store_id` | Random 128-bit identifier, lowercase hexadecimal |
| `salt` | 16 random bytes |
| `wrap_nonce` | 12 random bytes |
| `data_nonce` | 12 random bytes, distinct from the wrapping nonce |
| `kdf` | Argon2id name and integer memory/iteration/lane settings |

The default KDF uses 65,536 KiB, 3 iterations and 4 lanes. The parser accepts only
65,536–262,144 KiB, 3–10 iterations and 1–8 lanes. It checks these bounds before
starting the KDF. Passwords must be nonempty bytes, at most 4,096 bytes.

Canonical JSON sorts keys, uses compact separators and ASCII escapes, and rejects
non-finite numbers. The password-derived 256-bit key encrypts a random 256-bit
data key. AES-GCM produces a 48-byte wrapped key, including its authentication
tag. The data key encrypts the record document.

The wrapping operation authenticates the canonical header without `data_nonce`,
followed by a zero byte and `wrap`. Record encryption authenticates the complete
canonical header, `\0records\0` and the wrapped-key bytes. Excluding the changing
record nonce from the wrapping context lets an unlocked session update records
without retaining the password-derived key. The payload still authenticates that
nonce. Unlock succeeds only after both the wrapped key and payload are verified.

Every write samples a fresh nonce from the system cryptographic random source.
Immediate repeated or conflicting nonces are rejected. A password change also
generates a new salt and data key. Capturing an unlocked data key can still allow
decryption of a captured store; timeout or later rotation cannot revoke that copy.
Encryption alone cannot detect replacement with an older valid store.

## Explicit shared-store operations

`Vault.unlock(password)` loads one authenticated envelope. Ordinary reads keep
using that envelope. Another owner's append or deletion does not change cached
reads. An append from a stale owner still fails and locks that owner.

`Vault.reload() -> None` explicitly reads checked storage and authenticates it
with the already-unlocked owner's retained protected data key. It never requests
or retains a password. It requires the same wrapped key and stable header fields
(all except `data_nonce`). It accepts appended or deleted records, but rejects
changed values or metadata under a surviving ID. Successful reload preserves
session checkpoints, surviving references and their extraction metadata. A locked
vault cannot reload. Failed reload locks the owner and notifies its existing
listeners, including owners of borrowed key buffers. Password rotation requires
explicit unlock with the new password.

`Vault.delete_entries(selected: Iterable[str]) -> tuple[str, ...]` validates the
whole selection before writing. It accepts at most 4096 lowercase hexadecimal
record IDs of length 32. It rejects a bare string, malformed IDs and oversized
selections. Duplicates and already-absent IDs are harmless. The returned tuple
contains removed IDs in their previous record order. An empty or already-absent
selection checks storage freshness under the writer guard without rewriting.
A nonempty removal commits once with the existing checked storage identity.
Surviving IDs, metadata and value bytes stay unchanged. Replacement values need
an append with new IDs; captured snapshots are never edited in place.

A stale deletion or failed commit locks that owner. Failure after publication
can leave the complete new envelope visible. Unlock and reread before deciding
whether cleanup needs another attempt; do not retry blindly. Deletion is logical
cleanup, not erasure of old ciphertext, another owner's cached envelope or
previously returned plaintext. Other owners see deletions only after reload or
unlock. Application revocation and cross-file recovery remain host duties.

`CiphertextFile.writer_guard()` exposes the existing checked nonblocking POSIX
writer-lock scope. Contention raises `WriterBusy`. The scope releases on exit,
including exception or asynchronous task cancellation; process death releases
the kernel lock. Use one separate shared anchor path when coordinating work over
several files, whose own writes acquire their per-file guards. The anchor target
need not exist. The scope is not reentrant; do not nest a write on that same path.
Do not unlink or replace the associated lock file. Callers own bounded waiting,
retry, cancellation and recovery. This is an advisory lock for cooperating
processes, not an atomic cross-file transaction. Generic storage retains link
and identity checks and conservative creation modes. Applications own existing
owner/mode/ACL policy. Native Windows locking remains unavailable and unverified.

`tests/fixtures/vault-v1` contains a fixed synthetic file and its generation inputs
and hash. Its password and data key are public test values. The fixture was made
with cryptography 45.0.7 Argon2id and AESGCM. Keep it fixed across codec changes;
it does not contain a real wallet or credential. Its deterministic inputs must
never be used for real storage.
