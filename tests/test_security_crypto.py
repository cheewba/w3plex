"""Public byte encryption composes without a file or record format."""

import json
from dataclasses import replace

import pytest

from w3plex.security import crypto
from w3plex.security.errors import AuthenticationFailed, InvalidStore


def test_independently_encrypted_values_inside_an_encrypted_catalog():
    project_key = crypto.generate_key()
    salt = crypto.generate_salt()
    record_context = b"project/example/record/api-key"
    record_key = crypto.derive_subkey(project_key, salt=salt, context=record_context)
    value = b"PUBLIC-TEST-value\x00\xff"
    encrypted = crypto.seal(value, key=record_key, context=record_context)
    another = crypto.seal(value, key=record_key, context=record_context)
    assert encrypted.nonce != another.nonce
    assert (
        crypto.derive_subkey(project_key, salt=salt, context=record_context)
        == record_key
    )
    storage_key = crypto.derive_subkey(
        project_key, salt=salt, context=b"project/example/storage"
    )
    assert storage_key != record_key

    catalog = json.dumps(
        {"metadata": {"name": "api-key"}, "value": encrypted.to_data()}
    ).encode()
    outer = crypto.seal(catalog, key=storage_key, context=b"catalog")
    persisted = json.dumps({"_storage": outer.to_data()})
    assert value.decode("latin1") not in persisted and "api-key" not in persisted
    restored = crypto.EncryptedBlock.from_data(json.loads(persisted)["_storage"])
    catalog = json.loads(crypto.unseal(restored, key=storage_key, context=b"catalog"))
    assert catalog["metadata"] == {"name": "api-key"}
    restored = crypto.EncryptedBlock.from_data(catalog["value"])
    assert crypto.unseal(restored, key=record_key, context=record_context) == value


@pytest.mark.parametrize("change", ["ciphertext", "key", "context"])
def test_block_authentication_returns_no_plaintext(change):
    key, context = crypto.generate_key(), b"project/example/record"
    block = crypto.seal(b"PUBLIC-TEST-private", key=key, context=context)
    if change == "ciphertext":
        block = replace(
            block, ciphertext=block.ciphertext[:-1] + bytes([block.ciphertext[-1] ^ 1])
        )
    elif change == "key":
        key = crypto.generate_key()
    else:
        context = b"project/other/record"
    with pytest.raises(AuthenticationFailed) as raised:
        crypto.unseal(block, key=key, context=context)
    assert raised.value.__context__ is None and raised.value.__cause__ is None


def test_password_key_settings_and_block_validation():
    settings = crypto.KdfSettings()
    settings = crypto.KdfSettings.from_data(settings.to_data())
    salt = crypto.generate_salt()
    password = b"PUBLIC-TEST-password"
    key = crypto.derive_password_key(password, salt=salt, settings=settings)
    block = crypto.seal(b"", key=key, context=b"empty")
    assert (
        crypto.unseal(
            block,
            key=crypto.derive_password_key(password, salt=salt, settings=settings),
            context=b"empty",
        )
        == b""
    )
    with pytest.raises(InvalidStore):
        crypto.KdfSettings.from_data({**settings.to_data(), "memory_kib": 10**9})
    with pytest.raises(InvalidStore):
        crypto.EncryptedBlock.from_data({**block.to_data(), "nonce": ""})
