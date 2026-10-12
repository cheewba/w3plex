"""Private request lifetimes and distinct host/control and agent interfaces.

The application binds these interfaces to separately authenticated transports.
These objects are trusted in-process ports, not a replacement for OS/RPC
isolation. Do not serialize private requests or replies into ordinary events.
"""

import asyncio
import secrets
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated, Protocol

from .contracts import Public, Secret
from .diagnostics import private_async
from .errors import InteractionRequired, PermissionDenied, UnsupportedProtection
from .memory import ProcessProtection


class FieldKind(StrEnum):
    CHOICE = "choice"
    CONFIRM = "confirm"
    TEXT = "text"
    SECRET = "secret"


@dataclass(frozen=True, repr=False)
class InputField:
    name: str
    kind: FieldKind
    prompt: str
    choices: tuple[str, ...] = ()
    public: bool = False

    def __post_init__(self):
        if (
            not isinstance(self.kind, FieldKind)
            or type(self.public) is not bool
            or not isinstance(self.name, str)
            or not 1 <= len(self.name) <= 100
            or not isinstance(self.prompt, str)
            or len(self.prompt) > 4096
            or not isinstance(self.choices, tuple)
            or len(self.choices) > 64
            or any(
                not isinstance(value, str) or len(value) > 4096
                for value in self.choices
            )
        ):
            raise PermissionDenied()
        if self.kind is FieldKind.CHOICE and not self.choices:
            raise PermissionDenied()

    def __repr__(self):
        return "InputField(<private>)"


@dataclass(frozen=True, repr=False)
class PrivateRequest:
    operation: str
    step: str
    identifier: str
    fields: tuple[InputField, ...]
    expires_at: float

    def __repr__(self):
        return "PrivateRequest(<private>)"


@dataclass(frozen=True, repr=False)
class PrivateReply:
    operation: str
    step: str
    identifier: str
    values: Annotated[Mapping[str, str | bool], Secret]

    def __repr__(self):
        return "PrivateReply(<private>)"


@dataclass(frozen=True)
class AssistanceField:
    name: Annotated[str, Public]
    kind: Annotated[FieldKind, Public]
    prompt: Annotated[str, Public]
    choices: Annotated[tuple[str, ...], Public]


class PrivateInput(Protocol):
    async def ask(
        self,
        operation: str,
        step: str,
        fields: tuple[InputField, ...],
        *,
        timeout: float = 120,
    ) -> Annotated[PrivateReply, Secret]: ...


@dataclass(repr=False)
class _Pending:
    request: PrivateRequest
    future: asyncio.Future[PrivateReply]


class PrivateBroker:
    def __init__(
        self,
        *,
        interactive: bool,
        pause: Callable[[], Awaitable[None]],
        resume: Callable[[], Awaitable[None]],
        clock: Callable[[], float] = time.monotonic,
        protection: ProcessProtection | None = None,
    ):
        if type(interactive) is not bool:
            raise PermissionDenied()
        self._interactive = interactive
        self._protection = protection
        self._pause, self._resume, self._clock = pause, resume, clock
        self._pending: dict[str, _Pending] = {}
        self._operations: set[str] = set()
        self._assistance: set[str] = set()
        self._control_token = object()
        # The host serializes private dialogs so pause/resume cannot overlap.
        self._dialog = asyncio.Lock()

    def begin_operation(self) -> str:
        identifier = secrets.token_hex(16)
        self._operations.add(identifier)
        return identifier

    def finish_operation(self, operation: str):
        self._operations.discard(operation)
        for pending in tuple(self._pending.values()):
            if pending.request.operation == operation:
                self._assistance.discard(pending.request.identifier)
                if not pending.future.done():
                    pending.future.cancel()

    def cancel_all(self):
        for operation in tuple(self._operations):
            self.finish_operation(operation)

    def control_port(self) -> "ControlPort":
        """Trusted host construction only; never register this on agent RPC."""
        return ControlPort(self, self._control_token)

    def agent_port(self) -> "AgentPort":
        return AgentPort(self)

    @private_async
    async def ask(
        self,
        operation: str,
        step: str,
        fields: tuple[InputField, ...],
        *,
        timeout: float = 120,
    ) -> PrivateReply:
        if not self._interactive:
            raise InteractionRequired()
        if self._protection is None:
            raise UnsupportedProtection()
        self._protection.check()
        if (
            operation not in self._operations
            or not step
            or not fields
            or not 0 < timeout <= 600
            or len({field.name for field in fields}) != len(fields)
        ):
            raise PermissionDenied()
        async with self._dialog:
            if operation not in self._operations:
                raise PermissionDenied()
            request = PrivateRequest(
                operation, step, secrets.token_hex(16), fields, self._clock() + timeout
            )
            future = asyncio.get_running_loop().create_future()
            pending = _Pending(request, future)
            try:
                await self._pause()
                if operation not in self._operations:
                    raise PermissionDenied()
                self._pending[request.identifier] = pending
                expired = False
                reply = None
                try:
                    reply = await asyncio.wait_for(future, timeout)
                except TimeoutError:
                    expired = True
                if expired or reply is None:
                    raise InteractionRequired()
                if (
                    operation not in self._operations
                    or self._clock() >= request.expires_at
                ):
                    raise PermissionDenied()
                return reply
            finally:
                self._pending.pop(request.identifier, None)
                self._assistance.discard(request.identifier)
                await self._resume()

    def _answer(self, token: object, reply: PrivateReply):
        if token is not self._control_token:
            raise PermissionDenied()
        pending = self._pending.get(reply.identifier)
        if pending is None:
            raise PermissionDenied()
        request = pending.request
        if (
            pending.future.done()
            or request.operation not in self._operations
            or reply.operation != request.operation
            or reply.step != request.step
            or self._clock() >= request.expires_at
        ):
            raise PermissionDenied()
        if set(reply.values) != {field.name for field in request.fields}:
            raise PermissionDenied()
        for field in request.fields:
            value = reply.values[field.name]
            if field.kind is FieldKind.CONFIRM:
                valid = type(value) is bool
            else:
                valid = isinstance(value, str) and len(value) <= 4096
                if field.kind is FieldKind.CHOICE:
                    valid = valid and value in field.choices
            if not valid:
                raise PermissionDenied()
        # Copy into a private immutable envelope; caller mutation cannot change it.
        from types import MappingProxyType

        pending.future.set_result(
            PrivateReply(
                reply.operation,
                reply.step,
                reply.identifier,
                MappingProxyType(dict(reply.values)),
            )
        )


class ControlPort:
    def __init__(self, broker: PrivateBroker, token: object):
        if token is not broker._control_token:
            raise PermissionDenied()
        self._broker, self._token = broker, token

    def pending(self) -> tuple[PrivateRequest, ...]:
        return tuple(
            item.request
            for item in self._broker._pending.values()
            if not item.future.done()
        )

    def answer(self, reply: PrivateReply):
        self._broker._answer(self._token, reply)

    def allow_assistance(self, operation: str, *, allowed: bool):
        if type(allowed) is not bool or operation not in self._broker._operations:
            raise PermissionDenied()
        current = {
            pending.request.identifier
            for pending in self._broker._pending.values()
            if pending.request.operation == operation
            and not pending.future.done()
            and self._broker._clock() < pending.request.expires_at
        }
        if allowed:
            if not current:
                raise PermissionDenied()
            self._broker._assistance.update(current)
        else:
            self._broker._assistance.difference_update(current)

    def cancel(self, operation: str):
        self._broker.finish_operation(operation)


class AgentPort:
    def __init__(self, broker: PrivateBroker):
        self._broker = broker

    def assistance(self, operation: str) -> tuple[AssistanceField, ...]:
        return tuple(
            AssistanceField(field.name, field.kind, field.prompt, field.choices)
            for pending in self._broker._pending.values()
            if pending.request.operation == operation
            and pending.request.identifier in self._broker._assistance
            and not pending.future.done()
            and self._broker._clock() < pending.request.expires_at
            for field in pending.request.fields
            if field.public and field.kind is not FieldKind.SECRET
        )
