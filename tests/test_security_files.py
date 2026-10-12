"""File export authorization stays separate from the password dialog."""

import asyncio
import json
import os
from pathlib import Path

import pytest
from test_security_interaction_session import broker, make_session, pending, unlock

from w3plex.security.errors import PermissionDenied, SecurityError
from w3plex.security.files import FileClassification, FileExports
from w3plex.security.interaction import PrivateReply
from w3plex.security.legacy import LegacyContext

FIXTURES = Path(__file__).parent / "fixtures/legacy-security"


class Allow:
    def __init__(self):
        self.requests = []

    async def authorize(self, request):
        self.requests.append(request)
        return True


async def setup(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    session, private, hooks = make_session(tmp_path)
    await unlock(session, private)
    hooks.clear()
    legacy = LegacyContext(tmp_path / "absent-store")
    policy = Allow()
    exports = FileExports(
        work,
        protected_paths=(work / "protected",),
        legacy=legacy,
        private_input=private,
        authorizer=policy,
        session=session,
    )
    return work, private, hooks, legacy, policy, exports, session


def test_private_password_returns_only_approved_contents(tmp_path):
    async def check():
        work, private, hooks, legacy, policy, exports, session = await setup(tmp_path)
        path = work / "input.enc"
        path.write_bytes((FIXTURES / "sample.enc").read_bytes())
        reference = exports.register(path, classification=FileClassification.NONSECRET)
        operation = private.begin_operation()
        task = asyncio.create_task(exports.read(reference, operation=operation))
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
        assert await task == bytes.fromhex(manifest["plaintext_hex"])
        assert hooks == ["pause", "resume"]
        assert private.agent_port().assistance(operation) == ()
        assert "password" not in repr(policy.requests)
        # Cached reads need no new private input, but do need new authorization.
        assert await exports.read(reference, operation=operation) == bytes.fromhex(
            manifest["plaintext_hex"]
        )
        assert len(policy.requests) == 2
        assert hooks == ["pause", "resume"]
        await session.lock()
        assert legacy._keys is None
        with pytest.raises(PermissionDenied):
            await exports.read(reference, operation=operation)
        await session.close()

    asyncio.run(check())


def test_secret_unclassified_protected_paths_and_outside_work_are_denied(tmp_path):
    async def check():
        work, private, hooks, _legacy, policy, exports, session = await setup(tmp_path)
        source = work / "input.enc"
        source.write_bytes((FIXTURES / "sample.enc").read_bytes())
        for classification in (
            FileClassification.SECRET,
            FileClassification.UNCLASSIFIED,
        ):
            reference = exports.register(source, classification=classification)
            with pytest.raises(PermissionDenied):
                await exports.read(reference, operation=private.begin_operation())
        (work / "protected").mkdir()
        protected = work / "protected/config.enc"
        protected.write_bytes(source.read_bytes())
        reference = exports.register(
            protected, classification=FileClassification.NONSECRET
        )
        with pytest.raises(PermissionDenied):
            await exports.read(reference, operation=private.begin_operation())
        with pytest.raises(PermissionDenied):
            exports.register(
                tmp_path / "outside", classification=FileClassification.NONSECRET
            )
        assert policy.requests == [] and hooks == []
        await session.close()

    asyncio.run(check())


@pytest.mark.parametrize("action", ["change-file", "lock-context"])
def test_change_or_lock_during_private_input_prevents_export(tmp_path, action):
    async def check():
        work, private, hooks, legacy, _policy, exports, session = await setup(tmp_path)
        path = work / "input.enc"
        path.write_bytes((FIXTURES / "sample.enc").read_bytes())
        reference = exports.register(path, classification=FileClassification.NONSECRET)
        operation = private.begin_operation()
        task = asyncio.create_task(exports.read(reference, operation=operation))
        request = await pending(private.control_port())
        if action == "change-file":
            path.write_bytes(b"changed")
        else:
            legacy.lock()
        manifest = json.loads((FIXTURES / "manifest.json").read_text())
        private.control_port().answer(
            PrivateReply(
                operation,
                request.step,
                request.identifier,
                {"password": manifest["file_password"]},
            )
        )
        with pytest.raises(PermissionDenied):
            await task
        assert hooks == ["pause", "resume"]
        await session.close()

    asyncio.run(check())


def test_hardlink_and_symlink_inputs_do_not_escape_snapshot_checks(tmp_path):
    async def check():
        work, private, hooks, _legacy, policy, exports, session = await setup(tmp_path)
        path = work / "public"
        path.write_bytes(b"public data")
        os.link(path, work / "alias")
        reference = exports.register(path, classification=FileClassification.NONSECRET)
        with pytest.raises(PermissionDenied):
            await exports.read(reference, operation=private.begin_operation())
        (work / "alias").unlink()
        link = work / "symlink"
        link.symlink_to(path)
        reference = exports.register(link, classification=FileClassification.NONSECRET)
        with pytest.raises(SecurityError):
            await exports.read(reference, operation=private.begin_operation())
        assert hooks == [] and policy.requests == []
        await session.close()

    asyncio.run(check())


@pytest.mark.parametrize("approval", [False, 1, "yes", None])
def test_denied_authorization_never_prompts_or_decrypts(
    tmp_path, approval, monkeypatch
):
    async def check():
        work, private, hooks, legacy, policy, exports, session = await setup(tmp_path)
        path = work / "input.enc"
        path.write_bytes((FIXTURES / "sample.enc").read_bytes())
        reference = exports.register(path, classification=FileClassification.NONSECRET)

        async def authorize(_request):
            return approval

        monkeypatch.setattr(policy, "authorize", authorize)
        monkeypatch.setattr(
            legacy, "decrypt_private", lambda *a, **kw: pytest.fail("No decryption")
        )
        with pytest.raises(PermissionDenied):
            await exports.read(reference, operation=private.begin_operation())
        assert hooks == []
        await session.close()

    asyncio.run(check())


@pytest.mark.parametrize("change", ["file", "parent", "root"])
def test_snapshot_substitution_while_authorizing_is_rejected(tmp_path, change):
    async def check():
        work, private, hooks, _legacy, policy, exports, session = await setup(tmp_path)
        parent = work / "inputs"
        parent.mkdir()
        path = parent / "public"
        path.write_bytes(b"approved contents")
        reference = exports.register(path, classification=FileClassification.NONSECRET)

        async def authorize(_request):
            if change == "file":
                replacement = parent / "replacement"
                replacement.write_bytes(b"changed contents")
                replacement.replace(path)
            else:
                selected = parent if change == "parent" else work
                selected.rename(selected.with_name(selected.name + "-old"))
                selected.mkdir()
                if change == "root":
                    parent.mkdir()
                path.write_bytes(b"approved contents")
            return True

        policy.authorize = authorize
        with pytest.raises(PermissionDenied):
            await exports.read(reference, operation=private.begin_operation())
        assert hooks == []
        await session.close()

    asyncio.run(check())


def test_session_lock_during_password_input_cancels_read_and_stale_reply(tmp_path):
    async def check():
        work, private, hooks, legacy, _policy, exports, session = await setup(tmp_path)
        path = work / "input.enc"
        path.write_bytes((FIXTURES / "sample.enc").read_bytes())
        reference = exports.register(path, classification=FileClassification.NONSECRET)
        operation = private.begin_operation()
        task = asyncio.create_task(exports.read(reference, operation=operation))
        request = await pending(private.control_port())
        await session.lock()
        with pytest.raises(asyncio.CancelledError):
            await task
        with pytest.raises(PermissionDenied):
            private.control_port().answer(
                PrivateReply(
                    operation, request.step, request.identifier, {"password": "x"}
                )
            )
        assert legacy._keys is None
        assert hooks == ["pause", "resume"]
        await session.close()

    asyncio.run(check())


def test_plain_exports_need_no_unlock_but_encrypted_exports_require_session(tmp_path):
    async def check():
        work = tmp_path / "work"
        work.mkdir()
        legacy = LegacyContext(None)
        private, hooks = broker(interactive=False)
        # No private input should be invoked for either case.
        exports = FileExports(
            work,
            protected_paths=(),
            legacy=legacy,
            private_input=private,
            authorizer=Allow(),
        )
        path = work / "public"
        path.write_bytes(b"public contents")
        reference = exports.register(path, classification=FileClassification.NONSECRET)
        assert await exports.read(reference, operation="plain") == b"public contents"
        path.write_bytes((FIXTURES / "sample.enc").read_bytes())
        with pytest.raises(PermissionDenied):
            await exports.read(reference, operation="encrypted")
        assert hooks == []

    asyncio.run(check())
