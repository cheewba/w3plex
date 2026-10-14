"""Characterize public error codes and private-call boundaries before hardening."""

import asyncio
import inspect

import pytest

from w3plex.security.diagnostics import private_async
from w3plex.security.errors import (
    ActivationConflict,
    AuthenticationFailed,
    InteractionRequired,
    InvalidStore,
    PermissionDenied,
    SecurityError,
    UnsupportedProtection,
)
from w3plex.security.storage import StoreChanged, UnsafeStorage, WriterBusy
from w3plex.security.vault import private_call

ERRORS = (
    SecurityError,
    ActivationConflict,
    AuthenticationFailed,
    InteractionRequired,
    InvalidStore,
    PermissionDenied,
    UnsupportedProtection,
    StoreChanged,
    UnsafeStorage,
    WriterBusy,
)


@pytest.mark.parametrize("kind", ERRORS)
def test_private_boundaries_preserve_standard_error_types_without_causes(kind):
    def fail():
        raise kind()

    with pytest.raises(kind) as sync:
        private_call(fail)
    assert type(sync.value) is kind
    assert sync.value.__context__ is None and sync.value.__cause__ is None

    @private_async
    async def failure():
        fail()

    async def check():
        with pytest.raises(kind) as async_error:
            await failure()
        assert type(async_error.value) is kind
        assert (
            async_error.value.__context__ is None
            and async_error.value.__cause__ is None
        )

    asyncio.run(check())


def test_private_boundaries_preserve_return_values_and_async_signature():
    sentinel = object()
    assert private_call(lambda: sentinel) is sentinel

    async def original(value: object, *, option: bool = False) -> object:
        return value

    wrapped = private_async(original)
    assert inspect.signature(wrapped) == inspect.signature(original)
    assert asyncio.run(wrapped(sentinel, option=True)) is sentinel


def test_async_cancellation_uses_a_fresh_empty_exception():
    @private_async
    async def fail():
        raise asyncio.CancelledError("PUBLIC-TEST-private-cancel")

    async def check():
        with pytest.raises(asyncio.CancelledError) as error:
            await fail()
        assert error.value.args == ()
        assert error.value.__cause__ is None and error.value.__context__ is None

    asyncio.run(check())


def test_dependency_error_has_only_generic_public_code():
    def fail():
        raise ValueError("PUBLIC-TEST-private-dependency")

    with pytest.raises(SecurityError) as error:
        private_call(fail)
    assert type(error.value) is SecurityError and str(error.value) == "security_error"
    assert error.value.__cause__ is None and error.value.__context__ is None
