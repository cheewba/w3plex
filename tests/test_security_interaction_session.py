"""Private control/agent ports and lock races, without a model or live network."""

import asyncio

import pytest
from test_security_interaction import broker, pending

from w3plex.security.errors import (
    PermissionDenied,
    SecurityError,
)
from w3plex.security.interaction import (
    FieldKind,
    InputField,
    PrivateReply,
)
from w3plex.security.memory import ProcessProtection
from w3plex.security.session import Session, SessionState
from w3plex.security.storage import CiphertextFile
from w3plex.security.vault import Vault


def make_session(tmp_path, *, idle_seconds=10, clock=None):
    directory = tmp_path / "secrets"
    directory.mkdir(mode=0o700)
    protection = ProcessProtection()
    protection.activate()
    vault = Vault(CiphertextFile(directory / "vault"), protection=protection)
    vault.create(b"PUBLIC-TEST-password")
    private, hooks = broker()
    options = {} if clock is None else {"clock": clock}
    session = Session(
        vault,
        private_input=private,
        cancel_input=private.cancel_all,
        idle_seconds=idle_seconds,
        **options,
    )
    return session, private, hooks


async def unlock(session, private):
    op = private.begin_operation()
    task = asyncio.create_task(session.unlock(op))
    control = private.control_port()
    request = await pending(control)
    control.answer(
        PrivateReply(
            op, "unlock", request.identifier, {"password": "PUBLIC-TEST-password"}
        )
    )
    result = await task
    private.finish_operation(op)
    return result.generation


def test_unlock_once_polling_does_not_extend_idle_and_old_generation_is_refused(
    tmp_path,
):
    async def check():
        clock = [100.0]
        session, private, hooks = make_session(tmp_path, clock=lambda: clock[0])
        generation = await unlock(session, private)
        assert (await session.unlock("unused-operation")).generation == generation
        assert hooks == ["pause", "resume"]
        clock[0] = 105
        assert session.status().state is SessionState.UNLOCKED
        with pytest.raises(PermissionDenied):
            session.use("wrong-generation", "denied", lambda: None)
        clock[0] = 110
        with pytest.raises(PermissionDenied):
            session.use(
                generation, "queued", lambda: pytest.fail("Must not use secret")
            )
        await session.lock()
        assert session.status().state is SessionState.LOCKED
        assert session._vault._key is None
        next_generation = await unlock(session, private)
        assert next_generation != generation
        with pytest.raises(PermissionDenied):
            session.use(generation, "old", lambda: None)
        await session.close()
        assert session.status().state is SessionState.CLOSED

    asyncio.run(check())


def test_only_first_secret_use_of_operation_counts_as_activity(tmp_path):
    async def check():
        clock = [100.0]
        session, private, _ = make_session(tmp_path, clock=lambda: clock[0])
        generation = await unlock(session, private)
        clock[0] = 105
        session.check(generation)
        assert (
            session.use(generation, "operation", lambda: "public result")
            == "public result"
        )
        clock[0] = 114
        session.use(generation, "operation", lambda: None)
        clock[0] = 115
        with pytest.raises(PermissionDenied):
            session.use(generation, "operation", lambda: None)
        await session.close()

    asyncio.run(check())


def test_explicit_lock_cancels_pending_input_active_tasks_and_closes_credentials(
    tmp_path,
):
    async def check():
        session, private, _ = make_session(tmp_path)
        generation = await unlock(session, private)
        closed = []

        async def close():
            closed.append(True)

        task = asyncio.create_task(asyncio.Event().wait())
        session.track(generation, task, close=close)
        operation = private.begin_operation()
        dialog = asyncio.create_task(
            private.ask(
                operation, "confirm", (InputField("ok", FieldKind.CONFIRM, "Confirm"),)
            )
        )
        request = await pending(private.control_port())
        await session.lock()
        assert task.cancelled()
        assert closed == [True]
        with pytest.raises(asyncio.CancelledError):
            await dialog
        with pytest.raises(PermissionDenied):
            private.control_port().answer(
                PrivateReply(operation, "confirm", request.identifier, {"ok": True})
            )
        await session.close()

    asyncio.run(check())


def test_lock_during_unlock_prevents_late_secret_use_and_resume_stays_locked(tmp_path):
    async def check():
        session, private, _ = make_session(tmp_path)
        operation = private.begin_operation()
        task = asyncio.create_task(session.unlock(operation))
        request = await pending(private.control_port())
        await session.lock()
        with pytest.raises(asyncio.CancelledError):
            await task
        with pytest.raises(PermissionDenied):
            private.control_port().answer(
                PrivateReply(
                    operation,
                    "unlock",
                    request.identifier,
                    {"password": "PUBLIC-TEST-password"},
                )
            )
        assert session._vault._key is None
        await unlock(session, private)
        await session.suspend()
        await session.resume()
        assert session.status().state is SessionState.LOCKED
        await session.close()

    asyncio.run(check())


def test_lock_continues_cleanup_after_private_callback_and_closer_errors(tmp_path):
    async def check():
        session, private, _ = make_session(tmp_path)
        await unlock(session, private)
        calls = []

        def cancel_input():
            calls.append("cancel")
            raise RuntimeError("PUBLIC-TEST-private-callback-value")

        def broken_close():
            calls.append("broken")
            raise RuntimeError("PUBLIC-TEST-private-provider-value")

        async def close():
            calls.append("closed")

        session._cancel_input = cancel_input
        task = asyncio.current_task()
        assert task is not None
        generation = session.status().generation
        session.track(generation, task, close=broken_close)
        session.track(generation, task, close=close)
        with pytest.raises(SecurityError) as raised:
            await session.lock()
        assert raised.value.__cause__ is None and raised.value.__context__ is None
        assert set(calls) == {"cancel", "broken", "closed"}
        assert session.status().state is SessionState.LOCKED
        assert session._vault._key is None
        assert not session._closers and not session._tasks
        with pytest.raises(PermissionDenied):
            session.use(generation, "stale", lambda: None)
        # A completed failed cleanup is still reported, while close releases the vault.
        with pytest.raises(SecurityError):
            await session.close()
        assert session.status().state is SessionState.CLOSED

    asyncio.run(check())


def test_idle_timer_locks_without_polls_and_shutdown_releases_storage(tmp_path):
    async def check():
        session, private, hooks = make_session(tmp_path, idle_seconds=1)
        generation = await unlock(session, private)
        async with asyncio.timeout(5):
            await asyncio.shield(session._timer)
        assert session._state is SessionState.LOCKED
        assert session._vault._key is None
        assert hooks == ["pause", "resume"]
        with pytest.raises(PermissionDenied):
            session.use(generation, "expired", lambda: None)
        await session.close()
        assert session._vault._storage._fd is None
        assert session._state is SessionState.CLOSED

    asyncio.run(check())


def test_denied_consumer_does_not_refresh_idle_deadline(tmp_path):
    async def check():
        clock = [100.0]
        session, private, _ = make_session(tmp_path, clock=lambda: clock[0])
        generation = await unlock(session, private)
        clock[0] = 105

        def denied():
            raise PermissionDenied()

        session.check(generation)
        with pytest.raises(PermissionDenied):
            session.use(generation, "denied-consumer", denied)
        clock[0] = 110
        with pytest.raises(PermissionDenied):
            session.use(generation, "expired", lambda: None)
        await session.close()

    asyncio.run(check())
