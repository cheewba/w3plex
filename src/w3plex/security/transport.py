"""Registered HTTP operations. Credentials are injected inside the service only.

No redirects, host proxies, cookies, fallback URLs or WebSocket upgrades are
accepted. Each request gets a fresh DNS pin and a disposable connection pool.
Native TLS/Python buffers can make copies: closing them is not proof of erasure.
"""

import asyncio
import base64
import hashlib
import hmac
import ipaddress
import json
import math
import socket
from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated, Any, Protocol
from urllib.parse import quote, quote_plus, unquote

import aiohttp
from aiohttp.abc import AbstractResolver, ResolveResult
from yarl import URL

from .contracts import Public, SecretKind, SecretRef, SecretUse
from .diagnostics import private_async
from .errors import PermissionDenied, SecurityError, UnsupportedProtection
from .session import Session, SessionState
from .vault import Vault
from .vault_format import canonical


class AuthPlacement(StrEnum):
    HEADER = "header"
    QUERY = "query"
    PATH = "path"
    HMAC_SHA256 = "hmac_sha256"


class ResponseType(StrEnum):
    TEXT = "text"
    INTEGER = "integer"
    NUMBER = "number"
    BOOLEAN = "boolean"
    NULL = "null"


type ResponseShape = ResponseType | Mapping[str, ResponseShape] | tuple[ResponseShape]


@dataclass(frozen=True)
class RequestIntent:
    operation: Annotated[str, Public]
    registration: Annotated[str, Public]
    request_digest: Annotated[str, Public]
    secret: Annotated[SecretRef | None, Public]


@dataclass(frozen=True)
class ModelChunk:
    text: Annotated[str, Public]


class RequestAuthorizer(Protocol):
    async def authorize(self, request: RequestIntent) -> bool: ...


@dataclass(frozen=True, repr=False)
class RequestSpec:
    origin: str
    path: str
    method: str
    response_shape: ResponseShape
    parameters: tuple[str, ...] = ()
    body_fields: tuple[str, ...] = ()
    secret: SecretRef | None = None
    auth: AuthPlacement = AuthPlacement.HEADER
    auth_name: str = "Authorization"
    auth_prefix: str = "Bearer "
    stream_text_path: tuple[str | int, ...] | None = None

    def __repr__(self):
        return "RequestSpec(<private registration>)"


def _project(value, shape, depth=0):
    if depth > 32:
        raise SecurityError()
    if isinstance(shape, Mapping):
        if not isinstance(value, dict):
            raise SecurityError()
        return {
            key: _project(value[key], child, depth + 1)
            for key, child in shape.items()
            if key in value
        }
    if isinstance(shape, tuple) and len(shape) == 1:
        if not isinstance(value, list):
            raise SecurityError()
        return [_project(item, shape[0], depth + 1) for item in value]
    valid = (
        (shape is ResponseType.TEXT and type(value) is str)
        or (shape is ResponseType.INTEGER and type(value) is int)
        or (
            shape is ResponseType.NUMBER
            and (type(value) is int or (type(value) is float and math.isfinite(value)))
        )
        or (shape is ResponseType.BOOLEAN and type(value) is bool)
        or (shape is ResponseType.NULL and value is None)
    )
    if not valid:
        raise SecurityError()
    return value


class _SecretFilter:
    def __init__(self, secret: bytes | None):
        values: set[str] = set()
        if secret:
            values.update(
                (
                    secret.hex(),
                    secret.hex().upper(),
                    base64.b64encode(secret).decode(),
                    base64.urlsafe_b64encode(secret).decode(),
                )
            )
            try:
                text = secret.decode("utf-8")
            except UnicodeError:
                pass
            else:
                values.update((text, quote(text, safe=""), quote_plus(text)))
            values.update(value.rstrip("=") for value in tuple(values))
        self._patterns = tuple(value for value in values if value)
        self._hold = max((len(value) for value in self._patterns), default=1) - 1
        self._tail = ""

    def check_text(self, text: str):
        decoded = unquote(text)
        if any(value in text or value in decoded for value in self._patterns):
            raise SecurityError()

    def check(self, document):
        if isinstance(document, str):
            self.check_text(document)
        elif isinstance(document, dict):
            for key, value in document.items():
                self.check_text(key)
                self.check(value)
        elif isinstance(document, list):
            for value in document:
                self.check(value)

    def feed(self, text: str) -> str:
        self._tail += text
        self.check_text(self._tail)
        cut = max(0, len(self._tail) - self._hold)
        output, self._tail = self._tail[:cut], self._tail[cut:]
        return output

    def finish(self) -> str:
        self.check_text(self._tail)
        text, self._tail = self._tail, ""
        return text


class _PinnedResolver(AbstractResolver):
    def __init__(self, host: str, addresses: frozenset[str]):
        self._host, self._addresses = host, addresses

    async def resolve(self, host, port=0, family=socket.AF_INET) -> list[ResolveResult]:
        if host != self._host:
            raise PermissionDenied()
        return [
            {
                "hostname": host,
                "host": address,
                "port": port,
                "family": socket.AF_INET6 if ":" in address else socket.AF_INET,
                "proto": 0,
                "flags": socket.AI_NUMERICHOST,
            }
            for address in self._addresses
        ]

    async def close(self):
        pass


class _PinnedConnector(aiohttp.TCPConnector):
    def __init__(self, host: str, addresses: frozenset[str]):
        self._approved_addresses = addresses
        super().__init__(
            resolver=_PinnedResolver(host, addresses),
            use_dns_cache=False,
            force_close=True,
            limit=1,
            enable_cleanup_closed=True,
        )

    async def _wrap_create_connection(self, *args, **kwargs):
        transport, protocol = await super()._wrap_create_connection(*args, **kwargs)
        peer = transport.get_extra_info("peername")
        if (
            not peer
            or str(ipaddress.ip_address(peer[0])) not in self._approved_addresses
        ):
            transport.close()
            raise PermissionDenied()
        return transport, protocol


class ProtectedHTTP:
    """Trusted registry; model-facing callers receive registration names and DTOs.

    `allow_local_tests` is a host-only test option. Do not put it in agent settings.
    TLS uses aiohttp's default verified context. No caller SSL/proxy/header option
    is accepted. The supported connector ABI is aiohttp 3.11, checked in tests.
    """

    def __init__(
        self,
        vault: Vault,
        session: Session,
        *,
        authorizer: RequestAuthorizer | None,
        allow_local_tests: bool = False,
    ):
        if type(allow_local_tests) is not bool:
            raise PermissionDenied()
        self._vault, self._session, self._authorizer = vault, session, authorizer
        self._allow_local_tests = allow_local_tests
        self._registry: dict[str, RequestSpec] = {}
        self._clients: dict[aiohttp.ClientSession, asyncio.Task | None] = {}
        self._closed = False

    def __repr__(self):
        return "ProtectedHTTP(<private>)"

    def register(self, name: str, spec: RequestSpec):
        """Trusted host only. Never expose registration on agent RPC."""
        url = URL(spec.origin)
        if (
            not name
            or name in self._registry
            or spec.method not in {"GET", "POST"}
            or url.scheme
            not in ({"https", "http"} if self._allow_local_tests else {"https"})
            or not url.host
            or url.user is not None
            or url.password is not None
            or url.path not in {"", "/"}
            or url.query_string
            or url.fragment
        ):
            raise PermissionDenied()
        if (
            not spec.path.startswith("/")
            or spec.path.startswith("//")
            or "?" in spec.path
            or "#" in spec.path
            or not isinstance(spec.auth, AuthPlacement)
        ):
            raise PermissionDenied()
        if "{credential}" in spec.path and spec.auth is not AuthPlacement.PATH:
            raise PermissionDenied()
        if spec.auth is AuthPlacement.PATH and spec.path.count("{credential}") != 1:
            raise PermissionDenied()
        if spec.secret is not None and spec.secret.kind not in {
            SecretKind.API,
            SecretKind.RPC,
            SecretKind.MODEL,
        }:
            raise PermissionDenied()
        if (
            not spec.auth_name
            or any(
                character in spec.auth_name + spec.auth_prefix for character in "\r\n"
            )
            or spec.auth_name.lower()
            in {"host", "content-length", "transfer-encoding", "connection"}
        ):
            raise PermissionDenied()
        self._registry[name] = spec

    async def _resolve(self, host: str, port: int) -> frozenset[str]:
        addresses = await asyncio.get_running_loop().getaddrinfo(
            host, port, type=socket.SOCK_STREAM
        )
        approved = frozenset(
            str(ipaddress.ip_address(item[4][0])) for item in addresses
        )
        if not approved:
            raise PermissionDenied()
        for address in approved:
            ip = ipaddress.ip_address(address)
            if not self._allow_local_tests and (
                not ip.is_global or ip.is_multicast or ip.is_reserved
            ):
                raise PermissionDenied()
        return approved

    async def _prepare(
        self,
        name: str,
        *,
        operation: str,
        parameters: Mapping[str, str] | None,
        body: Mapping[str, Any] | None,
    ):
        spec = self._registry.get(name)
        if self._closed or spec is None or not operation or self._authorizer is None:
            raise PermissionDenied()
        params = dict(parameters or {})
        payload = json.loads(canonical(dict(body or {})))
        if (
            not set(params) <= set(spec.parameters)
            or not all(isinstance(value, str) for value in params.values())
            or not set(payload) <= set(spec.body_fields)
            or len(canonical(payload)) > 1024 * 1024
        ):
            raise PermissionDenied()
        if spec.auth is AuthPlacement.QUERY and spec.auth_name in params:
            raise PermissionDenied()
        intent = RequestIntent(
            operation,
            name,
            hashlib.sha256(
                canonical({"parameters": params, "body": payload})
            ).hexdigest(),
            spec.secret,
        )
        status = self._session.status()
        if await self._authorizer.authorize(intent) is not True:
            raise PermissionDenied()
        public_url = URL(spec.origin)
        host, port = public_url.host, public_url.port
        if host is None or port is None:
            raise PermissionDenied()
        addresses = await self._resolve(host, port)
        if self._closed:
            raise PermissionDenied()
        connector = _PinnedConnector(host, addresses)
        client = aiohttp.ClientSession(
            connector=connector,
            trust_env=False,
            cookie_jar=aiohttp.DummyCookieJar(),
            auto_decompress=False,
            timeout=aiohttp.ClientTimeout(total=120, connect=15),
        )
        self._clients[client] = asyncio.current_task()
        try:
            # aiohttp 3.11 may retry an idempotent request internally. Every
            # protected attempt must return through our session/destination guard.
            if type(getattr(client, "_retry_connection", None)) is not bool:
                raise UnsupportedProtection()
            client._retry_connection = False

            def authenticate(secret: bytes | None):
                headers = {}
                path = spec.path
                if secret is not None:
                    if spec.auth is AuthPlacement.HMAC_SHA256:
                        headers[spec.auth_name] = hmac.new(
                            secret, canonical(payload), hashlib.sha256
                        ).hexdigest()
                    else:
                        text = secret.decode("utf-8")
                        if any(
                            ord(character) < 32 or ord(character) == 127
                            for character in text
                        ):
                            raise PermissionDenied()
                        if spec.auth is AuthPlacement.HEADER:
                            headers[spec.auth_name] = spec.auth_prefix + text
                        elif spec.auth is AuthPlacement.QUERY:
                            params[spec.auth_name] = text
                        elif spec.auth is AuthPlacement.PATH:
                            path = path.replace("{credential}", quote(text, safe=""))
                url = public_url.with_path(path, encoded=True).with_query(params)
                return (
                    spec,
                    client,
                    url,
                    headers,
                    payload,
                    _SecretFilter(secret),
                    status.generation if spec.secret is not None else None,
                )

            if spec.secret is None:
                return authenticate(None)
            secret_reference = spec.secret
            if status.state is not SessionState.UNLOCKED:
                raise PermissionDenied()
            task = asyncio.current_task()
            if task is None:
                raise PermissionDenied()
            self._session.track(status.generation, task, close=client.close)
            return self._session.use(
                status.generation,
                operation,
                lambda: self._vault._use_secret(
                    secret_reference, SecretUse.HTTP, authenticate
                ),
            )
        except BaseException:
            await self._close_client(client)
            raise

    async def _close_client(self, client: aiohttp.ClientSession) -> None:
        try:
            await client.close()
        finally:
            self._clients.pop(client, None)
            task = asyncio.current_task()
            if task is not None:
                self._session.untrack(task, close=client.close)

    @private_async
    async def request(
        self,
        name: str,
        *,
        operation: str,
        parameters: Mapping[str, str] | None = None,
        body: Mapping[str, Any] | None = None,
    ):
        spec, client, url, headers, payload, filter_, generation = await self._prepare(
            name, operation=operation, parameters=parameters, body=body
        )
        try:
            async with client.request(
                spec.method,
                url,
                headers=headers,
                json=payload if spec.method == "POST" else None,
                allow_redirects=False,
            ) as response:
                if (
                    response.status not in {200, 201}
                    or response.headers.get("Content-Encoding", "identity")
                    != "identity"
                    or response.content_type != "application/json"
                ):
                    raise SecurityError()
                chunks = []
                size = 0
                async for chunk in response.content.iter_chunked(16384):
                    size += len(chunk)
                    if size > 2 * 1024 * 1024:
                        raise SecurityError()
                    chunks.append(chunk)
                result = _project(json.loads(b"".join(chunks)), spec.response_shape)
                filter_.check(result)
                if self._closed:
                    raise PermissionDenied()
                if generation is not None:
                    self._session.check(generation)
                return result
        finally:
            headers.clear()
            await self._close_client(client)

    async def stream(
        self, name: str, *, operation: str, body: Mapping[str, Any]
    ) -> AsyncIterator[ModelChunk]:
        """Bounded SSE text stream; hold a tail to catch keys split across frames."""
        error = False
        cancelled = False
        try:
            (
                spec,
                client,
                url,
                headers,
                payload,
                filter_,
                generation,
            ) = await self._prepare(
                name, operation=operation, parameters=None, body=body
            )
            try:
                if spec.stream_text_path is None:
                    raise PermissionDenied()
                async with client.request(
                    spec.method,
                    url,
                    headers=headers,
                    json=payload,
                    allow_redirects=False,
                ) as response:
                    if (
                        response.status != 200
                        or response.content_type != "text/event-stream"
                        or response.headers.get("Content-Encoding", "identity")
                        != "identity"
                    ):
                        raise SecurityError()
                    size = 0
                    async for line in response.content:
                        if self._closed:
                            raise PermissionDenied()
                        if generation is not None:
                            self._session.check(generation)
                        size += len(line)
                        if size > 2 * 1024 * 1024:
                            raise SecurityError()
                        if not line.startswith(b"data:"):
                            continue
                        frame = line[5:].strip()
                        if frame == b"[DONE]":
                            break
                        projected = _project(json.loads(frame), spec.response_shape)
                        value: Any = projected
                        for part in spec.stream_text_path:
                            value = value[part]
                        if not isinstance(value, str):
                            raise SecurityError()
                        text = filter_.feed(value)
                        if text:
                            yield ModelChunk(text)
                    tail = filter_.finish()
                    if self._closed:
                        raise PermissionDenied()
                    if generation is not None:
                        self._session.check(generation)
                    if tail:
                        yield ModelChunk(tail)
            finally:
                headers.clear()
                await self._close_client(client)
        except asyncio.CancelledError:
            cancelled = True
        except Exception:  # noqa: BLE001 -- stream errors never expose private dependency state
            error = True
        if cancelled:
            raise asyncio.CancelledError()
        if error:
            raise SecurityError()

    @private_async
    async def close(self):
        self._closed = True
        clients, self._clients = self._clients, {}
        current = asyncio.current_task()
        tasks = {
            task
            for task in clients.values()
            if task is not None and task is not current
        }
        for task in tasks:
            task.cancel()
        results = await asyncio.gather(
            *(client.close() for client in clients), return_exceptions=True
        )
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        if any(isinstance(result, BaseException) for result in results):
            raise SecurityError()
