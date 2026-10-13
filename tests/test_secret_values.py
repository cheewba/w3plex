"""Derived references keep extraction recipes rather than decoded values."""

from dataclasses import FrozenInstanceError

import pytest

from w3plex.security import SecretJson, SecretString
from w3plex.security.errors import InvalidStore, SecurityError

PASSWORD = b"PUBLIC-TEST-snapshot-password"


def test_unicode_ranges_use_bytes_and_survive_lock(secret_store):
    root = secret_store.capture("zero café end".encode())
    text = SecretString(root, 5, len("café".encode()))
    assert text.ref(silent=True) == "café"
    secret_store._vault.lock()
    secret_store._vault.unlock(PASSWORD)
    assert text.ref(silent=True) == "café"
    assert "café" not in repr(text)
    with pytest.raises(FrozenInstanceError):
        text.offset = 0


def test_json_escapes_and_nested_text_restore_with_one_confirmation(secret_store):
    root = secret_store.capture(b'{"wallets":[{"key":"abc\\u0031xyz"}]}')
    document = SecretJson(root)
    key = document["wallets"][0]["key"]
    selected = SecretString(key, 3, 1)
    confirmations = []
    secret_store._confirm = lambda access: confirmations.append(access) or True
    assert selected.ref() == "1"
    assert len(confirmations) == 1
    assert confirmations[0].identifier == root.identifier
    secret_store._vault.lock()
    secret_store._vault.unlock(PASSWORD)
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


@pytest.mark.parametrize("offset,length", [(-1, 1), (0, -1), (True, 1)])
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


def test_depth_is_bounded_and_equivalent_recipes_keep_selection_identity(secret_store):
    root = secret_store.capture(b"test")
    assert SecretString(root) == SecretString(root)
    parent = root
    for _ in range(32):
        parent = SecretString(parent)
    with pytest.raises(InvalidStore):
        SecretString(parent)
