"""Consumers support independent structural references without a base class."""

import asyncio

import pytest
from eth_account import Account as EthAccount
from eth_account.messages import encode_defunct

from w3plex.security import ISecretRef, SecretJson, SecretString
from w3plex.security.errors import PermissionDenied, SecurityError
from w3plex.utils.loader import FileLoader
from w3plex.w3 import Account

KEY = "0x" + "01" * 32


class ExternalRef[T]:
    def __init__(self, value: T):
        self.value = value
        self.locked = False
        self.calls = []

    def ref(self, *, silent=False) -> T:
        self.calls.append(silent)
        if self.locked:
            raise PermissionDenied()
        return self.value


def test_account_uses_custom_reference_without_retaining_plaintext():
    source = ExternalRef(KEY)
    assert isinstance(source, ISecretRef)
    account = Account.from_key(source)
    assert account.key is source
    message = encode_defunct(text="public protocol test")
    signature = account.sign_message(message)
    assert (
        EthAccount.recover_message(message, signature=signature.signature)
        == account.address
    )
    assert source.calls and all(source.calls)
    source.locked = True
    with pytest.raises(PermissionDenied):
        account.sign_message(message)


def test_adapters_and_existing_reader_accept_custom_reference():
    source = ExternalRef(b'{"items":["one","caf\\u00e9"]}')
    value = SecretString(SecretJson[str](source, ("items", 1)))
    assert isinstance(value, ISecretRef)
    assert value.ref() == "café"
    assert source.calls and not any(source.calls)
    lines = asyncio.run(FileLoader(file=ExternalRef(b"one\ntwo\n")).process())
    assert [line.ref(silent=True) for line in lines] == ["one", "two"]


def test_reference_errors_are_sanitized_at_the_consumer():
    class BrokenRef:
        def ref(self, *, silent=False):
            raise ValueError("PUBLIC-TEST-private-key-error")

    with pytest.raises(SecurityError) as caught:
        Account.from_key(BrokenRef())
    assert "PUBLIC-TEST-private-key-error" not in str(caught.value)
    assert caught.value.__context__ is None
