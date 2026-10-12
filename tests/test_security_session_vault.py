"""Vault failures invalidate the session's legacy keys and credential work."""

import asyncio
import json
from pathlib import Path

import pytest
from test_security_files import setup as setup_files
from test_security_interaction_session import make_session, pending, unlock
from test_security_transport import Client, Response
from test_security_transport import setup as setup_http

from w3plex.security.contracts import SecretKind, SecretUse
from w3plex.security.errors import PermissionDenied, SecurityError
from w3plex.security.files import FileClassification
from w3plex.security.interaction import PrivateReply
from w3plex.security.session import Session, SessionState
from w3plex.security.transport import RequestSpec, ResponseType

FIXTURES = Path(__file__).parent / "fixtures/legacy-security"


def test_lock_closes_connections_before_waiting_for_cancelled_workers(tmp_path):
    async def check():
        session, private, _ = make_session(tmp_path)
        generation = await unlock(session, private)
        entered, closed = asyncio.Event(), asyncio.Event()

        async def close():
            closed.set()

        async def worker():
            entered.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                # A dependency may need its connection closed to finish cleanup.
                await closed.wait()

        task = asyncio.create_task(worker())
        await entered.wait()
        session.track(generation, task, close=close)
        try:
            async with asyncio.timeout(1):
                await session.lock()
            assert closed.is_set() and task.done()
            assert session.status().state is SessionState.LOCKED
        finally:
            closed.set()
            await asyncio.gather(task, return_exceptions=True)
            await session.close()

    asyncio.run(check())


def test_failed_vault_write_immediately_revokes_generation(tmp_path, monkeypatch):
    async def check():
        session, private, _ = make_session(tmp_path)
        generation = await unlock(session, private)
        original = session._vault._storage.path.read_bytes()

        def failed_write(*args, **kwargs):
            raise OSError("PUBLIC-TEST-private-write-error")

        monkeypatch.setattr(session._vault._storage, "write", failed_write)
        with pytest.raises(SecurityError):
            session.use(
                generation,
                "import",
                lambda: session._vault.add(
                    SecretKind.API, b"PUBLIC-TEST-new-api", uses=[SecretUse.HTTP]
                ),
            )
        # A write failure deliberately locks Vault; Session must agree immediately.
        assert session.status().state in {SessionState.LOCKING, SessionState.LOCKED}
        assert session.status().generation != generation
        assert session._vault._key is None
        assert session._vault._storage.path.read_bytes() == original
        with pytest.raises(PermissionDenied):
            session.check(generation)
        await session.lock()
        next_generation = await unlock(session, private)
        assert next_generation != generation
        await session.close()

    asyncio.run(check())


def test_vault_lock_prevents_cached_legacy_read_and_clears_context(tmp_path):
    async def check():
        work, private, _hooks, legacy, _policy, exports, session = await setup_files(
            tmp_path
        )
        path = work / "input.enc"
        path.write_bytes((FIXTURES / "sample.enc").read_bytes())
        reference = exports.register(path, classification=FileClassification.NONSECRET)
        operation = private.begin_operation()
        read = asyncio.create_task(exports.read(reference, operation=operation))
        request = await pending(private.control_port())
        manifest = json.loads((FIXTURES / "manifest.json").read_text())
        private.control_port().answer(
            PrivateReply(
                operation,
                request.step,
                request.identifier,
                {"password": manifest["file_password"]},
            )
        )
        assert await read == bytes.fromhex(manifest["plaintext_hex"])
        assert legacy._keys is not None
        generation = session.status().generation
        session._vault.lock()
        with pytest.raises(PermissionDenied):
            await exports.read(reference, operation=operation)
        await session.lock()
        assert legacy._keys is None and session.status().generation != generation
        assert not private.control_port().pending()
        await session.close()

    asyncio.run(check())


@pytest.mark.parametrize("action", ["write-failure", "vault-lock"])
def test_vault_lock_cancels_already_authenticated_http(tmp_path, monkeypatch, action):
    async def check():
        session, reference, _policy, http = await setup_http(tmp_path, monkeypatch)
        generation = session.status().generation
        http.register(
            "read",
            RequestSpec(
                "https://public.example",
                "/read",
                "GET",
                {"result": ResponseType.TEXT},
                secret=reference,
            ),
        )
        entered = asyncio.Event()

        class WaitingContent:
            async def iter_chunked(self, size):
                entered.set()
                await asyncio.Event().wait()
                yield b"{}"

        Client.response = Response({})
        Client.response.content = WaitingContent()
        task = asyncio.create_task(http.request("read", operation="active"))
        await entered.wait()

        def failed_write(*args, **kwargs):
            raise OSError("PUBLIC-TEST-private-write-error")

        if action == "write-failure":
            monkeypatch.setattr(session._vault._storage, "write", failed_write)
            with pytest.raises(SecurityError):
                session.use(
                    generation,
                    "import",
                    lambda: session._vault.add(
                        SecretKind.API, b"PUBLIC-TEST-new-api", uses=[SecretUse.HTTP]
                    ),
                )
        else:
            session._vault.lock()
        # No status poll or explicit lock is needed to start connection cleanup.
        assert session._cleanup is not None
        await asyncio.shield(session._cleanup)
        with pytest.raises(asyncio.CancelledError):
            await task
        assert Client.instances[0].closed and not http._clients
        assert not session._tasks and not session._closers
        await session.close()

    asyncio.run(check())


def test_one_session_owns_vault_lock_without_invalidating_existing_owner(tmp_path):
    async def check():
        session, private, _ = make_session(tmp_path)
        generation = await unlock(session, private)
        with pytest.raises(PermissionDenied):
            Session(
                session._vault, private_input=private, cancel_input=private.cancel_all
            )
        assert session.status().state is SessionState.UNLOCKED
        assert session.status().generation == generation
        session._vault.lock()
        assert session._cleanup is not None and session._generation != generation
        await session.lock()
        await session.close()
        assert session._vault._lock_listener is None

    asyncio.run(check())


def test_nested_queued_tracking_does_not_remove_parent_operation(tmp_path):
    async def check():
        session, private, _ = make_session(tmp_path)
        generation = await unlock(session, private)
        task = asyncio.current_task()
        session.track(generation, task)
        session.track(generation, task)
        session.untrack(task, close=None)
        assert task in session._tasks
        session.untrack(task, close=None)
        assert task not in session._tasks
        await session.close()

    asyncio.run(check())


def test_password_change_revokes_old_session_even_after_direct_reunlock(tmp_path):
    async def check():
        session, private, _ = make_session(tmp_path)
        generation = await unlock(session, private)
        session.use(
            generation,
            "change-password",
            lambda: session._vault.change_password(
                b"PUBLIC-TEST-password", b"PUBLIC-TEST-replacement"
            ),
        )
        assert session._generation != generation
        # Trusted hosts must unlock through Session. Even this direct vault call
        # must not revive old permissions or leave its data key after cleanup.
        session._vault.unlock(b"PUBLIC-TEST-replacement")
        with pytest.raises(PermissionDenied):
            session.check(generation)
        await session.lock()
        assert not session._vault.is_unlocked
        await session.close()

    asyncio.run(check())
