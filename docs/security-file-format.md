# Encrypted external-file format

`W3FILE1` stores one authenticated text or binary payload. It differs from
`W3VAULT1`, which stores records and metadata. The low-level codec is in
`w3plex.security.file_format`; automatic open and CLI integration are separate
work and must not be assumed from the codec alone.

The on-disk layout is:

| Field | Bytes |
| --- | --- |
| Magic `W3FILE1\n` | 8 |
| Header length, unsigned big-endian integer | 4 |
| JSON header | 1 to 4096 |
| Wrapped file key, including GCM tag | 48 |
| Encrypted file bytes, including GCM tag | 16 to 64 MiB + 16 |

The header has exactly these fields: `version`, `cipher`, `context`, `file_id`,
`kdf`, `salt`, `wrap_nonce`, and `data_nonce`. Version is the integer `1`, cipher
is `AES-256-GCM`, and context is `w3plex.file`. The file ID is 32 lowercase hex
characters. Salt is 16 bytes; each nonce is 12 bytes. Binary header values use
standard Base64. Duplicate JSON fields and non-finite numbers are rejected.

The KDF object has exactly `name`, `memory_kib`, `iterations`, and `lanes`.
Name is `argon2id`. Defaults are 65536 KiB, three iterations and four lanes.
The reader accepts 65536–262144 KiB, 3–10 iterations and 1–8 lanes. The password
is 1–4096 bytes. Size and KDF checks precede expensive work.

Encryption creates a fresh random 32-byte file key. Argon2id derives a 32-byte
wrapping key from the password and fresh salt. AES-256-GCM encrypts both the
file key and the payload, with separate fresh nonces and full 128-bit tags.
The writer refuses an equal wrapping and payload nonce.

For authenticated metadata, canonical JSON uses sorted keys, ASCII escaping,
compact separators and no non-finite numbers. Associated data is:

- Key wrapping: magic, `\0key\0`, canonical header.
- Payload: magic, `\0file\0`, canonical header, wrapped file key.

The displayed `\0` denotes a zero byte. Both steps authenticate all header
fields. The payload also authenticates the wrapped key, including when the
reader already has a cached file key. Wrong passwords or modified data return
`AuthenticationFailed` without plaintext or a dependency exception chain.
Missing algorithms return `UnsupportedProtection`; there is no weaker retry.

The whole payload is authenticated before it is returned. This format supports
any byte contents up to 64 MiB, without streaming or unauthenticated seeks.
The codec makes temporary immutable Python and cryptography copies; it does
not provide memory isolation, authorization or revocation of returned bytes.
The host must establish its required process controls before handling secrets.

Earlier w3plex readers cannot read this format. ENC1 and KS01 retain their own
format and algorithms; upgrading does not strengthen or rewrite old files.
The fixed sample under `tests/fixtures/file-v1` uses public synthetic values
and was generated independently with direct cryptography 45.0.7 calls.

See [cryptography 45.0.7 AEAD](https://cryptography.io/en/45.0.7/hazmat/primitives/aead/)
and [Argon2id](https://cryptography.io/en/45.0.7/hazmat/primitives/key-derivation-functions/#argon2id).
These references describe the primitives, not an audit of the container.
