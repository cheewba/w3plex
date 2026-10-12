"""Real local TLS/SSE probe for registered HTTP, using a fake vault host port.

Run in a disposable container with --network none. This is component evidence,
not a full vault, native-wheel or agent acceptance run. The generated TLS key
belongs only to this temporary test server. No wallet or real API key is used.
"""

import asyncio
import importlib
import json
import os
import platform
import ssl
import subprocess
import sys
import tempfile
import types
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[2] / "src/w3plex/security"
package = types.ModuleType("security_http_probe")
package.__path__ = [str(SOURCE)]
sys.modules[package.__name__] = package


async def probe(certificate, keyfile):
    # Import after selecting the test-only trust root, so aiohttp initializes
    # its ordinary verified TLS context. The registry accepts no SSL override.
    from aiohttp import web

    contracts = importlib.import_module(package.__name__ + ".contracts")
    errors = importlib.import_module(package.__name__ + ".errors")
    memory = importlib.import_module(package.__name__ + ".memory")
    controls = memory.ProcessProtection()
    controls.activate()
    marker = b"PUBLIC-TEST-http-credential-78213"
    reference = contracts.SecretRef("ab" * 16, contracts.SecretKind.API)

    class FakeVault:
        def __init__(self):
            self.buffer = None
            self.listener = None

        def _bind_lock(self, callback):
            self.listener = callback

        @property
        def is_unlocked(self):
            return self.buffer is not None

        def unlock(self, password):
            assert password == b"PUBLIC-TEST-password"
            self.buffer = memory.LockedBuffer(marker, protection=controls)

        def _use_secret(self, ref, use, consumer):
            assert ref == reference and use is contracts.SecretUse.HTTP
            assert self.buffer is not None
            return consumer(self.buffer.copy_bytes())

        def lock(self):
            if self.buffer is not None:
                self.buffer.close()
                self.buffer = None
            if self.listener is not None:
                self.listener()

        def close(self):
            self.lock()

    fake_module = types.ModuleType(package.__name__ + ".vault")
    fake_module.Vault = FakeVault
    fake_module._private = lambda consumer: consumer()
    sys.modules[fake_module.__name__] = fake_module
    session_module = importlib.import_module(package.__name__ + ".session")
    interaction = importlib.import_module(package.__name__ + ".interaction")
    # transport needs only canonical JSON from the format module, not this
    # probe's fake vault. Load the real codec dependency through a minimal port.
    codec_module = types.ModuleType(package.__name__ + ".vault_format")
    codec_module.canonical = lambda value: json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")
    sys.modules[codec_module.__name__] = codec_module
    transport = importlib.import_module(package.__name__ + ".transport")

    async def no_hook():
        return None

    private = interaction.PrivateBroker(
        interactive=True, pause=no_hook, resume=no_hook, protection=controls
    )
    vault = FakeVault()
    session = session_module.Session(
        vault, private_input=private, cancel_input=private.cancel_all
    )
    op = private.begin_operation()
    task = asyncio.create_task(session.unlock(op))
    while not private.control_port().pending():
        await asyncio.sleep(0)
    request = private.control_port().pending()[0]
    private.control_port().answer(
        interaction.PrivateReply(
            op, request.step, request.identifier, {"password": "PUBLIC-TEST-password"}
        )
    )
    await task
    private.finish_operation(op)

    seen = []
    trap = []
    entered = asyncio.Event()
    release = asyncio.Event()

    async def handler(request):
        seen.append(request.headers.get("Authorization"))
        assert request.headers.get("Authorization") == "Bearer " + marker.decode()
        if request.path == "/ok":
            return web.json_response(
                {"result": "public balance", "private_unknown": marker.decode()}
            )
        if request.path == "/echo":
            return web.json_response({"result": marker.decode()})
        if request.path == "/redirect":
            raise web.HTTPFound("/trap")
        if request.path == "/trap":
            trap.append(True)
            return web.json_response({"result": "bad"})
        if request.path == "/wait":
            entered.set()
            await release.wait()
            return web.json_response({"result": "delayed"})
        response = web.StreamResponse(headers={"Content-Type": "text/event-stream"})
        await response.prepare(request)
        parts = (
            ["hello ", "world"]
            if request.path == "/stream"
            else [marker.decode()[:8], marker.decode()[8:16], marker.decode()[16:]]
        )
        for part in parts:
            await response.write(
                b"data: " + json.dumps({"delta": part}).encode() + b"\n\n"
            )
        await response.write(b"data: [DONE]\n\n")
        return response

    app = web.Application()
    app.router.add_route("*", "/{path}", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, keyfile)
    site = web.TCPSite(runner, "127.0.0.1", 0, ssl_context=context)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]

    class Authorizer:
        async def authorize(self, intent):
            assert marker.decode() not in repr(intent)
            return True

    http = transport.ProtectedHTTP(
        vault, session, authorizer=Authorizer(), allow_local_tests=True
    )
    # A host proxy environment must not affect the protected connection.
    os.environ["HTTPS_PROXY"] = "http://wrong-proxy.invalid:9"
    origin = f"https://127.0.0.1:{port}"
    for path in ("ok", "echo", "redirect", "wait", "stream", "split"):
        stream = path in {"stream", "split"}
        spec = transport.RequestSpec(
            origin,
            "/" + path,
            "POST" if stream else "GET",
            {"delta" if stream else "result": transport.ResponseType.TEXT},
            secret=reference,
            body_fields=("prompt",) if stream else (),
            stream_text_path=("delta",) if stream else None,
        )
        http.register(path, spec)
    # Pin a wrong hostname to the real local server: certificate validation
    # must fail before the application receives an authenticated HTTP request.
    http.register(
        "wrong-tls-name",
        transport.RequestSpec(
            origin.replace("127.0.0.1", "wrong-name.invalid"),
            "/ok",
            "GET",
            {"result": transport.ResponseType.TEXT},
            secret=reference,
        ),
    )
    original_resolver = http._resolve

    async def test_address(host, port):
        assert host == "wrong-name.invalid"
        return frozenset({"127.0.0.1"})

    http._resolve = test_address
    try:
        await http.request("wrong-tls-name", operation="wrong-tls-name")
    except errors.SecurityError as error:
        assert error.__context__ is None and marker.decode() not in str(error)
    else:
        raise AssertionError("TLS accepted a wrong certificate hostname")
    finally:
        http._resolve = original_resolver
    assert seen == [] and not http._clients
    assert await http.request("ok", operation="ok") == {"result": "public balance"}
    for registration in ("echo", "redirect"):
        try:
            await http.request(registration, operation=registration)
        except errors.SecurityError as error:
            assert error.__context__ is None and marker.decode() not in str(error)
        else:
            raise AssertionError("Unsafe response accepted")
    assert trap == []
    chunks = [
        chunk.text
        async for chunk in http.stream(
            "stream", operation="stream", body={"prompt": "public prompt"}
        )
    ]
    assert "".join(chunks) == "hello world"
    emitted = []
    try:
        async for chunk in http.stream(
            "split", operation="split", body={"prompt": "public prompt"}
        ):
            emitted.append(chunk.text)
    except errors.SecurityError as error:
        assert error.__context__ is None
    else:
        raise AssertionError("Split secret accepted")
    assert emitted == []
    waiting = asyncio.create_task(http.request("wait", operation="wait"))
    await entered.wait()
    await session.lock()
    try:
        await waiting
    except asyncio.CancelledError:
        pass
    else:
        raise AssertionError("Lock did not cancel HTTP")
    release.set()
    assert not http._clients
    await http.close()
    await session.close()
    await runner.cleanup()
    print(
        json.dumps(
            {
                "platform": platform.platform(),
                "python": platform.python_version(),
                "tls": "verified with a temporary test-only trust root",
                "wrong_tls_hostname": "blocked before credential transmission",
                "credential_injection": "passed",
                "private_response_fields": "filtered",
                "echo": "blocked",
                "redirect": "blocked",
                "model_stream": "passed",
                "split_key": "blocked before emission",
                "lock_cancellation": "passed",
                "host_ports": "fake vault; real session, broker, native controls and HTTP",
                "limits": "No full vault/agent acceptance or production native dependency wheel was tested.",
            }
        )
    )


def main():
    with tempfile.TemporaryDirectory(prefix="cryptopal-http-probe-") as directory:
        certificate = str(Path(directory) / "cert.pem")
        keyfile = str(Path(directory) / "key.pem")
        # Set owner access before OpenSSL creates this synthetic server key.
        old_umask = os.umask(0o077)
        try:
            subprocess.run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-keyout",
                    keyfile,
                    "-out",
                    certificate,
                    "-days",
                    "1",
                    "-subj",
                    "/CN=localhost",
                    "-addext",
                    "subjectAltName=IP:127.0.0.1,DNS:localhost",
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=20,
            )
        finally:
            os.umask(old_umask)
        os.environ["SSL_CERT_FILE"] = certificate
        asyncio.run(asyncio.wait_for(probe(certificate, keyfile), timeout=30))


if __name__ == "__main__":
    main()
