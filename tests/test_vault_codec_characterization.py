"""Characterize the existing V1 byte format before sharing crypto primitives."""

import hashlib
import json
from pathlib import Path

import pytest

from w3plex.security import vault_format as codec
from w3plex.security.errors import AuthenticationFailed

FIXTURES = Path(__file__).parent / "fixtures/vault-v1"


def sample():
    manifest = json.loads((FIXTURES / "manifest.json").read_text())
    raw = (FIXTURES / "sample.vault").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == manifest["sha256"]["sample.vault"]
    return raw, manifest


def test_fixed_v1_key_and_plaintext_remain_readable_without_rewriting():
    raw, manifest = sample()
    envelope = codec.parse(raw)
    key = codec.unwrap(envelope, manifest["password"].encode())
    assert key.hex() == manifest["data_key_hex"]
    assert codec.open_payload(envelope, key).hex() == manifest["plaintext_hex"]
    assert envelope.serialize() == raw


def test_v1_record_update_keeps_the_existing_password_wrapper():
    raw, manifest = sample()
    envelope = codec.parse(raw)
    key = bytes.fromhex(manifest["data_key_hex"])
    updated = codec.update_payload(envelope, key, b'{"records":[]}')
    assert updated.wrapped_key == envelope.wrapped_key
    assert {k: v for k, v in updated.header.items() if k != "data_nonce"} == {
        k: v for k, v in envelope.header.items() if k != "data_nonce"
    }
    assert codec.unwrap(updated, manifest["password"].encode()) == key
    assert codec.open_payload(updated, key) == b'{"records":[]}'


def test_cached_v1_key_still_authenticates_header_changes():
    raw, manifest = sample()
    document = json.loads(raw[len(codec.MAGIC) :])
    document["header"]["store_id"] = "0" * 32
    changed = codec.parse(codec.MAGIC + codec.canonical(document))
    with pytest.raises(AuthenticationFailed) as raised:
        codec.open_payload(changed, bytes.fromhex(manifest["data_key_hex"]))
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
