"""Derived references keep extraction recipes rather than decoded values."""

from dataclasses import FrozenInstanceError

import pytest

from w3plex.security import SecretJson, SecretStore, SecretString
from w3plex.security.errors import InvalidStore, SecurityError


def test_unicode_ranges_use_bytes_and_survive_lock(vault, vault_password, secret_store):
    root = secret_store.capture("zero café end".encode())
    text = SecretString(root, 5, len("café".encode()))
    assert text.ref(silent=True) == "café"
    vault.lock()
    vault.unlock(vault_password)
    assert text.ref(silent=True) == "café"
    assert "café" not in repr(text)
    with pytest.raises(FrozenInstanceError):
        text.offset = 0


def test_json_escapes_and_nested_text_restore_with_one_confirmation(
    vault, vault_password
):
    confirmations = []
    secret_store = SecretStore(
        vault, confirm=lambda access: confirmations.append(access) or True
    )
    root = secret_store.capture(b'{"wallets":[{"key":"abc\\u0031xyz"}]}')
    document = SecretJson(root)
    key = document["wallets"][0]["key"]
    selected = SecretString(key, 3, 1)
    assert selected.ref() == "1"
    assert len(confirmations) == 1
    assert confirmations[0].identifier == root.identifier
    vault.lock()
    vault.unlock(vault_password)
    assert key.ref(silent=True) == "abc1xyz"
    assert selected.ref(silent=True) == "1"
    assert all("abc1xyz" not in repr(item) for item in [root, document, key, selected])


@pytest.mark.parametrize(
    "raw,path",
    [
        (b'{"a":1,"a":2}', ("a",)),
        (b'{"a":NaN}', ("a",)),
        (b'{"a":', ("a",)),
        (b'{"a":[]}', ("a", 0)),
        (b'{"a":1}', ("missing",)),
        (b"[1]", ("0",)),
    ],
)
def test_bad_json_paths_and_formats_do_not_disclose_data(secret_store, raw, path):
    value = SecretJson(secret_store.capture(raw), path)
    with pytest.raises(SecurityError) as caught:
        value.ref(silent=True)
    assert caught.value.__context__ is None
    assert raw.decode() not in str(caught.value)


@pytest.mark.parametrize("offset,length", [(-1, 1), (0, -1)])
def test_invalid_range_metadata_is_rejected(secret_store, offset, length):
    with pytest.raises(InvalidStore):
        SecretString(secret_store.capture(b"test"), offset, length)


def test_out_of_bounds_wrong_parent_and_split_unicode_are_safe(secret_store):
    root = secret_store.capture("é".encode())
    for item in [
        SecretString(root, 3),
        SecretString(root, 0, 3),
        SecretString(root, 0, 1),
        SecretString(SecretJson(secret_store.capture(b'{"a":1}'))),
    ]:
        with pytest.raises(SecurityError):
            item.ref(silent=True)
