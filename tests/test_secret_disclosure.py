"""Warning suppression is not permission and cannot resurrect stale disclosure."""

import json
from dataclasses import FrozenInstanceError

import pytest
from test_secret_snapshots import PASSWORD, VALUE

from w3plex.security.errors import InteractionRequired, PermissionDenied, SecurityError
from w3plex.security.refs import AccessKind, SecretStore


def test_default_disclosure_confirms_without_sending_secret_to_callback(secret_store):
    calls = []
    ref = secret_store.capture(VALUE)
    secret_store._confirm = lambda access: calls.append(access) or True
    assert ref.ref() == VALUE
    assert len(calls) == 1
    assert calls[0].action is AccessKind.DISCLOSE
    assert calls[0].identifier == ref.identifier
    assert VALUE.decode() not in repr(calls)


def test_missing_confirmation_and_refusal_return_no_value(secret_store):
    ref = secret_store.capture(VALUE)
    with pytest.raises(InteractionRequired):
        ref.ref()
    for reply in [False, None, 1, "yes"]:
        secret_store._confirm = lambda access, reply=reply: reply
        with pytest.raises(PermissionDenied):
            ref.ref()


def test_silent_is_explicit_and_does_not_skip_authorization_or_lock(secret_store):
    ref = secret_store.capture(VALUE)
    assert ref.ref(silent=True) == VALUE
    calls = []
    secret_store._authorize = lambda access: calls.append(access.action) or False
    with pytest.raises(PermissionDenied):
        ref.ref(silent=True)
    assert calls == [AccessKind.DISCLOSE]
    secret_store._authorize = None
    secret_store._vault.lock()
    with pytest.raises(PermissionDenied):
        ref.ref(silent=True)


def test_lock_reunlock_during_confirmation_invalidates_attempt(secret_store):
    ref = secret_store.capture(VALUE)

    def confirm(access):
        secret_store._vault.lock()
        secret_store._vault.unlock(PASSWORD)
        return True

    secret_store._confirm = confirm
    with pytest.raises(PermissionDenied):
        ref.ref()
    assert ref.ref(silent=True) == VALUE


def test_permission_revocation_during_confirmation_prevents_disclosure(secret_store):
    ref = secret_store.capture(VALUE)
    secret_store._authorize = lambda access: True

    def confirm(access):
        secret_store._authorize = lambda access: False
        return True

    secret_store._confirm = confirm
    with pytest.raises(PermissionDenied):
        ref.ref()


def test_confirmation_errors_have_safe_codes_and_no_dependency_chain(secret_store):
    ref = secret_store.capture(VALUE)

    class PrivateError(SecurityError):
        def __init__(self):
            Exception.__init__(self, VALUE.decode())

    def failed(access):
        raise PrivateError()

    secret_store._confirm = failed
    with pytest.raises(SecurityError) as caught:
        ref.ref()
    assert type(caught.value) is SecurityError
    assert VALUE.decode() not in str(caught.value)
    assert caught.value.__context__ is None
    assert caught.value.__cause__ is None


def test_conversion_and_reference_mutation_never_reveal_values(secret_store):
    ref = secret_store.capture(VALUE)
    assert VALUE.decode() not in str(ref)
    with pytest.raises(TypeError):
        json.dumps(ref)
    with pytest.raises(FrozenInstanceError):
        ref._source = None
    with pytest.raises(PermissionDenied):
        ref.ref(silent=1)
    other = SecretStore(secret_store._vault)
    with pytest.raises(PermissionDenied):
        other._use(ref, lambda value: value)
