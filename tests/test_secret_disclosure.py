"""Explicit disclosure warnings and lock races for generic references."""

import json
from dataclasses import FrozenInstanceError

import pytest

from w3plex.security import SecretStore, SecretString
from w3plex.security.errors import InteractionRequired, PermissionDenied, SecurityError

VALUE = b"PUBLIC-TEST-disclosure-value"


def test_default_disclosure_confirms_without_exposing_the_value(vault):
    calls = []
    secret_store = SecretStore(
        vault, confirm=lambda request: calls.append(request) or True
    )
    source = secret_store.capture(VALUE)
    assert source.ref() == VALUE
    assert len(calls) == 1
    assert calls[0].identifier == source.identifier
    assert VALUE.decode() not in repr(calls)


def test_missing_confirmation_and_refusal_return_no_value(vault, secret_store):
    source = secret_store.capture(VALUE)
    with pytest.raises(InteractionRequired):
        source.ref()
    for reply in [False, None, 1, "yes"]:
        refusing_store = SecretStore(vault, confirm=lambda request, reply=reply: reply)
        with pytest.raises(PermissionDenied):
            refusing_store.reference(source.identifier).ref()


@pytest.mark.parametrize("child", [False, True])
def test_lock_reunlock_during_confirmation_invalidates_disclosure(
    vault, vault_password, child
):
    def confirm(request):
        vault.lock()
        vault.unlock(vault_password)
        return True

    root = SecretStore(vault, confirm=confirm).capture(VALUE)
    source = SecretString(root) if child else root
    with pytest.raises(PermissionDenied):
        source.ref()
    assert source.ref(silent=True) == (VALUE.decode() if child else VALUE)


def test_confirmation_errors_have_safe_codes_without_dependency_chain(vault):
    class PrivateError(SecurityError):
        def __init__(self):
            Exception.__init__(self, VALUE.decode())

    def failed(request):
        raise PrivateError()

    source = SecretStore(vault, confirm=failed).capture(VALUE)
    with pytest.raises(SecurityError) as caught:
        source.ref()
    assert type(caught.value) is SecurityError
    assert VALUE.decode() not in str(caught.value)
    assert caught.value.__context__ is None and caught.value.__cause__ is None


def test_representation_and_mutation_do_not_reveal_values(secret_store):
    source = secret_store.capture(VALUE)
    assert VALUE.decode() not in str(source)
    with pytest.raises(TypeError):
        json.dumps(source)
    with pytest.raises(FrozenInstanceError):
        source.identifier = "0" * 32
    with pytest.raises(PermissionDenied):
        source.ref(silent=1)
