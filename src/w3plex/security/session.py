"""Monotonic session lifetimes; unlocking never grants operation permission."""

import asyncio
import secrets
import threading
import time
from collections import Counter
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated

from .contracts import Public
from .diagnostics import private_async
from .errors import PermissionDenied, SecurityError
from .interaction import FieldKind, InputField, PrivateInput
from .vault import Vault, _private


class SessionState(StrEnum):
    LOCKED = "locked"
    UNLOCKING = "unlocking"
    UNLOCKED = "unlocked"
    LOCKING = "locking"
    CLOSED = "closed"


@dataclass(frozen=True)
class SessionStatus:
    state: Annotated[SessionState, Public]
    generation: Annotated[str, Public]


class Session:
    def __init__(
        self,
        vault: Vault,
        *,
        private_input: PrivateInput,
        cancel_input: Callable[[], None],
        idle_seconds: float = 900,
        clock: Callable[[], float] = time.monotonic,
    ):
        if isinstance(idle_seconds, bool) or not 1 <= idle_seconds <= 86400:
            raise ValueError("Invalid inactivity period")
        self._vault = vault
        self._input, self._cancel_input = private_input, cancel_input
        self._idle_seconds, self._clock = idle_seconds, clock
        self._state = SessionState.LOCKED
        self._generation = secrets.token_hex(16)
        self._deadline = 0.0
        self._used_operations: set[str] = set()
        self._mutex = threading.RLock()
        self._timer: asyncio.Task[None] | None = None
        self._cleanup: asyncio.Task[None] | None = None
        self._tasks: dict[
            asyncio.Task, Counter[Callable[[], Awaitable[None]] | None]
        ] = {}
        self._closers: set[Callable[[], Awaitable[None]]] = set()
        self._closing = False
        self._vault._bind_lock(self._vault_locked)
        self._vault.lock()

    def __repr__(self):
        return "Session(<private>)"

    def _vault_locked(self) -> None:
        # Session-owned vault operations run on the host event loop.
        with self._mutex:
            if self._state is SessionState.UNLOCKED:
                self._start_lock()

    def _start_lock(self):
        """Called on the host event loop while holding the short mutex."""
        if self._state in {
            SessionState.LOCKED,
            SessionState.CLOSED,
            SessionState.LOCKING,
        }:
            return
        self._state = SessionState.LOCKING
        self._generation = secrets.token_hex(16)
        self._used_operations.clear()
        failed = False
        try:
            self._cancel_input()
        except Exception:  # noqa: BLE001 -- cleanup must continue after private callback failure
            failed = True
        try:
            self._vault.lock()
        except Exception:  # noqa: BLE001 -- still cancel tasks and close credential resources
            failed = True
        current = asyncio.current_task()
        if self._timer is not None and self._timer is not current:
            self._timer.cancel()
        tasks = tuple(
            task for task in self._tasks if task is not current and not task.done()
        )
        self._tasks.clear()
        for task in tasks:
            task.cancel()
        closers, self._closers = tuple(self._closers), set()
        self._cleanup = asyncio.create_task(self._finish_lock(tasks, closers, failed))

    async def _finish_lock(self, tasks, closers, failed):
        async def close_one(close):
            await close()

        results = await asyncio.gather(
            *(close_one(close) for close in closers), return_exceptions=True
        )
        # Closing a connection can be needed for a cancelled worker to finish.
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        with self._mutex:
            try:
                self._vault.lock()
            except Exception:  # noqa: BLE001 -- finish invalidating the session after cleanup failure
                failed = True
            self._state = SessionState.CLOSED if self._closing else SessionState.LOCKED
        if failed or any(isinstance(result, BaseException) for result in results):
            raise SecurityError()

    def status(self) -> SessionStatus:
        with self._mutex:
            if self._state is SessionState.UNLOCKED and (
                self._clock() >= self._deadline or not self._vault.is_unlocked
            ):
                self._start_lock()
            return SessionStatus(self._state, self._generation)

    async def unlock(self, operation: str) -> SessionStatus:
        """Private host operation. Password fields never become tool arguments."""
        with self._mutex:
            current = self.status()
            if current.state is SessionState.UNLOCKED:
                return current
            if current.state is not SessionState.LOCKED or self._closing:
                raise PermissionDenied()
            self._state = SessionState.UNLOCKING
            generation = self._generation
        succeeded = False
        try:
            reply = await self._input.ask(
                operation,
                "unlock",
                (
                    InputField(
                        "password", FieldKind.SECRET, "Unlock the encrypted store"
                    ),
                ),
            )
            password = reply.values.get("password")
            if not isinstance(password, str):
                raise PermissionDenied()
            with self._mutex:
                if (
                    self._generation != generation
                    or self._state is not SessionState.UNLOCKING
                    or self._closing
                ):
                    raise PermissionDenied()
                self._vault.unlock(password.encode("utf-8"))
                self._generation = secrets.token_hex(16)
                self._state = SessionState.UNLOCKED
                self._deadline = self._clock() + self._idle_seconds
                self._timer = asyncio.create_task(self._watch_idle(self._generation))
                succeeded = True
                return self.status()
        finally:
            if not succeeded:
                with self._mutex:
                    if (
                        self._generation == generation
                        and self._state is SessionState.UNLOCKING
                    ):
                        self._vault.lock()
                        self._state = SessionState.LOCKED

    async def _watch_idle(self, generation: str):
        while True:
            with self._mutex:
                if (
                    self._state is not SessionState.UNLOCKED
                    or self._generation != generation
                ):
                    return
                delay = self._deadline - self._clock()
            if delay <= 0:
                await self.lock()
                return
            await asyncio.sleep(delay)

    def _check_generation(self, generation: str):
        if self._state is SessionState.UNLOCKED and (
            self._clock() >= self._deadline or not self._vault.is_unlocked
        ):
            self._start_lock()
        if (
            self._state is not SessionState.UNLOCKED
            or self._generation != generation
            or self._closing
        ):
            raise PermissionDenied()

    def use[T](self, generation: str, operation: str, consumer: Callable[[], T]) -> T:
        """Private adapter guard after permission admission, just before secret use.

        Consumers are synchronous, bounded secret work (signing or injection).
        They cannot await or retain secret values in model-facing objects.
        """
        with self._mutex:
            self._check_generation(generation)
            if not operation:
                raise PermissionDenied()
            try:
                result = _private(consumer)
            finally:
                # Password changes and failed writes can lock Vault during use.
                if not self._vault.is_unlocked:
                    self._start_lock()
            if (
                self._state is SessionState.UNLOCKED
                and operation not in self._used_operations
            ):
                self._used_operations.add(operation)
                self._deadline = self._clock() + self._idle_seconds
            return result

    def check(self, generation: str) -> None:
        """Guard work that does not use a secret, without refreshing activity."""
        with self._mutex:
            self._check_generation(generation)

    def track(
        self,
        generation: str,
        task: asyncio.Task,
        *,
        close: Callable[[], Awaitable[None]] | None = None,
    ):
        """Track credential work so lock cancels tasks and closes its resources."""
        with self._mutex:
            self._check_generation(generation)
            if task not in self._tasks:
                self._tasks[task] = Counter()
                task.add_done_callback(self._forget_task)
            self._tasks[task][close] += 1
            if close is not None:
                self._closers.add(close)

    def _forget_task(self, task: asyncio.Task) -> None:
        with self._mutex:
            self._tasks.pop(task, None)

    def untrack(
        self, task: asyncio.Task, *, close: Callable[[], Awaitable[None]] | None
    ) -> None:
        """Release tracking after a disposable credential resource has closed."""
        with self._mutex:
            resources = self._tasks.get(task)
            if resources is not None:
                if resources[close] > 1:
                    resources[close] -= 1
                else:
                    resources.pop(close, None)
                if not resources:
                    self._tasks.pop(task, None)
            if close is not None and not any(
                close in resource for resource in self._tasks.values()
            ):
                self._closers.discard(close)

    async def lock(self):
        with self._mutex:
            self._start_lock()
            cleanup = self._cleanup
        if cleanup is not None:
            await asyncio.shield(cleanup)

    async def suspend(self):
        await self.lock()

    async def resume(self):
        await self.lock()

    @private_async
    async def close(self):
        with self._mutex:
            self._closing = True
        try:
            await self.lock()
        finally:
            try:
                self._cancel_input()
            finally:
                with self._mutex:
                    self._vault._bind_lock(None)
                    self._vault.close()
                    self._state = SessionState.CLOSED
