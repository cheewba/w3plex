"""Explicit disclosure warnings and lock races for generic references."""

import json
from dataclasses import FrozenInstanceError

import pytest
from test_secret_snapshots import PASSWORD, VALUE

from w3plex.security import SecretString
from w3plex.security.errors import InteractionRequired, PermissionDenied, SecurityError


def test_default_disclosure_confirms_without_exposing_the_value(secret_store):
    calls = []
    source = secret_store.capture(VALUE)
    secret_store._confirm = lambda request: calls.append(request) or True
    assert source.ref() == VALUE
    assert len(calls) == 1
    assert calls[0].identifier == source.identifier
    assert VALUE.decode() not in repr(calls)


def test_missing_confirmation_and_refusal_return_no_value(secret_store):
    source = secret_store.capture(VALUE)
    with pytest.raises(InteractionRequired):
        source.ref()
    for reply in [False, None, 1, "yes"]:
        secret_store._confirm = lambda request, reply=reply: reply
        with pytest.raises(PermissionDenied):
            source.ref()


def test_silent_retrieval_still_requires_unlock(secret_store):
    source = secret_store.capture(VALUE)
    assert source.ref(silent=True) == VALUE
    secret_store._vault.lock()
    with pytest.raises(PermissionDenied):
        source.ref(silent=True)


@pytest.mark.parametrize("child", [False, True])
def test_lock_reunlock_during_confirmation_invalidates_disclosure(secret_store, child):
    root = secret_store.capture(VALUE)
    source = SecretString(root) if child else root

    def confirm(request):
        secret_store._vault.lock()
        secret_store._vault.unlock(PASSWORD)
        return True

    secret_store._confirm = confirm
    with pytest.raises(PermissionDenied):
        source.ref()
    assert source.ref(silent=True) == (VALUE.decode() if child else VALUE)


def test_confirmation_errors_have_safe_codes_without_dependency_chain(secret_store):
    source = secret_store.capture(VALUE)

    class PrivateError(SecurityError):
        def __init__(self):
            Exception.__init__(self, VALUE.decode())

    def failed(request):
        raise PrivateError()

    secret_store._confirm = failed
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
