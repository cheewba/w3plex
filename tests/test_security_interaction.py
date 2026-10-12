"""Private reply binding, terminal refusal and scoped nonsecret assistance."""

import asyncio
import getpass
from unittest.mock import Mock

import pytest

from w3plex.security.errors import (
    InteractionRequired,
    PermissionDenied,
    SecurityError,
    UnsupportedProtection,
)
from w3plex.security.interaction import (
    ControlPort,
    FieldKind,
    InputField,
    PrivateBroker,
    PrivateReply,
)
from w3plex.security.memory import ProcessProtection


def broker(*, interactive=True, clock=None):
    hooks = []

    async def pause():
        hooks.append("pause")

    async def resume():
        hooks.append("resume")

    options = {} if clock is None else {"clock": clock}
    controls = ProcessProtection()
    if interactive:
        controls.activate()
    options["protection"] = controls
    return PrivateBroker(
        interactive=interactive, pause=pause, resume=resume, **options
    ), hooks


async def pending(control):
    for _ in range(10):
        requests = control.pending()
        if requests:
            return requests[0]
        await asyncio.sleep(0)
    raise AssertionError("No private request")


def test_noninteractive_input_has_no_stdin_or_getpass_fallback(monkeypatch):
    stdin = Mock(side_effect=AssertionError("No echoed input"))
    secret_input = Mock(side_effect=AssertionError("No secret input fallback"))
    monkeypatch.setattr("builtins.input", stdin)
    monkeypatch.setattr(getpass, "getpass", secret_input)

    async def check():
        private, hooks = broker(interactive=False)
        with pytest.raises(InteractionRequired) as raised:
            await private.ask(
                private.begin_operation(),
                "unlock",
                (InputField("password", FieldKind.SECRET, "Private"),),
            )
        assert raised.value.code == "interaction_required"
        assert raised.value.__cause__ is None and raised.value.__context__ is None
        assert private.control_port().pending() == () and hooks == []

    asyncio.run(check())
    stdin.assert_not_called()
    secret_input.assert_not_called()


def test_private_pause_failure_resumes_and_exposes_only_safe_status(caplog):
    async def check():
        resumed = []

        async def pause():
            raise RuntimeError("PUBLIC-TEST-private-pause-value")

        async def resume():
            resumed.append(True)

        controls = ProcessProtection()
        controls.activate()
        private = PrivateBroker(
            interactive=True, pause=pause, resume=resume, protection=controls
        )
        with pytest.raises(SecurityError) as raised:
            await private.ask(
                private.begin_operation(),
                "step",
                (InputField("password", FieldKind.SECRET, "Private"),),
            )
        assert str(raised.value) == "security_error"
        assert raised.value.__cause__ is None and raised.value.__context__ is None
        assert private.control_port().pending() == () and resumed == [True]

    asyncio.run(check())
    assert "PUBLIC-TEST-private-pause-value" not in caplog.text


def test_missing_process_controls_refuse_private_input_before_pause():
    async def check():
        called = []

        async def hook():
            called.append(True)

        private = PrivateBroker(interactive=True, pause=hook, resume=hook)
        with pytest.raises(UnsupportedProtection):
            await private.ask(
                private.begin_operation(),
                "step",
                (InputField("password", FieldKind.SECRET, "Unlock"),),
            )
        assert called == []
        assert private.control_port().pending() == ()

    asyncio.run(check())


def test_private_reply_matching_duplicate_replay_and_no_agent_answer():
    async def check():
        private, hooks = broker()
        control, agent = private.control_port(), private.agent_port()
        op = private.begin_operation()
        task = asyncio.create_task(
            private.ask(
                op, "step", (InputField("secret", FieldKind.SECRET, "private prompt"),)
            )
        )
        request = await pending(control)
        assert not hasattr(agent, "answer") and not hasattr(agent, "pending")
        assert agent.assistance(op) == ()
        with pytest.raises(PermissionDenied):
            ControlPort(private, object())
        for operation, step, identifier in [
            ("wrong", "step", request.identifier),
            (op, "wrong", request.identifier),
            (op, "step", "unknown"),
        ]:
            with pytest.raises(PermissionDenied):
                control.answer(
                    PrivateReply(
                        operation, step, identifier, {"secret": "PUBLIC-TEST-secret"}
                    )
                )
        reply = PrivateReply(
            op, "step", request.identifier, {"secret": "PUBLIC-TEST-secret"}
        )
        assert "PUBLIC-TEST-secret" not in repr(reply)
        assert "private prompt" not in repr(request)
        control.answer(reply)
        with pytest.raises(PermissionDenied):
            control.answer(reply)
        result = await task
        assert result.values["secret"] == "PUBLIC-TEST-secret"
        with pytest.raises(TypeError):
            result.values["secret"] = "changed"
        with pytest.raises(PermissionDenied):
            control.answer(reply)
        assert hooks == ["pause", "resume"]
        private.finish_operation(op)

    asyncio.run(check())


def test_nonsecret_assistance_requires_per_operation_consent_and_revocation():
    async def check():
        private, _ = broker()
        control, agent = private.control_port(), private.agent_port()
        first, second = private.begin_operation(), private.begin_operation()
        fields = (
            InputField("public", FieldKind.TEXT, "Public question", public=True),
            InputField("secret", FieldKind.SECRET, "Secret question", public=True),
            InputField("unknown", FieldKind.TEXT, "Private by default"),
        )
        task = asyncio.create_task(private.ask(first, "step", fields))
        await pending(control)
        assert agent.assistance(first) == ()
        with pytest.raises(PermissionDenied):
            control.allow_assistance(first, allowed="false")
        control.allow_assistance(first, allowed=True)
        assert [field.name for field in agent.assistance(first)] == ["public"]
        assert agent.assistance(second) == ()
        control.allow_assistance(first, allowed=False)
        assert agent.assistance(first) == ()
        control.cancel(first)
        with pytest.raises(asyncio.CancelledError):
            await task
        assert agent.assistance(first) == ()
        private.cancel_all()

    asyncio.run(check())


def test_expiry_cancel_and_noninteractive_never_read_stdin(monkeypatch):
    monkeypatch.setattr("builtins.input", Mock(side_effect=AssertionError("No stdin")))

    async def check():
        quiet, hooks = broker(interactive=False)
        with pytest.raises(InteractionRequired):
            await quiet.ask(
                quiet.begin_operation(),
                "step",
                (InputField("password", FieldKind.SECRET, "private"),),
            )
        assert hooks == []
        clock = [10.0]
        private, hooks = broker(clock=lambda: clock[0])
        control = private.control_port()
        op = private.begin_operation()
        task = asyncio.create_task(
            private.ask(
                op, "step", (InputField("text", FieldKind.TEXT, "private"),), timeout=1
            )
        )
        request = await pending(control)
        clock[0] = request.expires_at
        with pytest.raises(PermissionDenied):
            control.answer(
                PrivateReply(op, "step", request.identifier, {"text": "value"})
            )
        control.cancel(op)
        with pytest.raises(asyncio.CancelledError):
            await task
        with pytest.raises(PermissionDenied):
            control.answer(
                PrivateReply(op, "step", request.identifier, {"text": "value"})
            )
        assert hooks == ["pause", "resume"]

    asyncio.run(check())


def test_cancel_during_pause_cannot_publish_new_request():
    async def check():
        paused = asyncio.Event()
        release = asyncio.Event()
        resumed = []

        async def pause():
            paused.set()
            await release.wait()

        async def resume():
            resumed.append(True)

        controls = ProcessProtection()
        controls.activate()
        private = PrivateBroker(
            interactive=True, pause=pause, resume=resume, protection=controls
        )
        op = private.begin_operation()
        task = asyncio.create_task(
            private.ask(op, "step", (InputField("text", FieldKind.TEXT, "private"),))
        )
        await paused.wait()
        private.finish_operation(op)
        release.set()
        with pytest.raises(PermissionDenied):
            await task
        assert not private.control_port().pending()
        assert resumed == [True]

    asyncio.run(check())
