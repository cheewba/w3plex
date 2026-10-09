import asyncio
import subprocess
import sys

import pytest

from w3plex.modules.debank import Debank
from w3plex.modules.odos import Odos
from w3plex.modules.proxy import ProxyPool
from w3plex.plugins.dashboard import DashboardManager, DashboardPage


def test_http_clients_create_sessions_lazily_and_close_them():
    clients = [Debank(), Odos(None, None)]

    async def check():
        for client in clients:
            assert client._session is None
            async with client:
                session = await client.get_session()
                assert not session.closed
            assert session.closed
            await client.close()

    asyncio.run(check())


def test_proxy_pool_initializes_once_and_returns_cancelled_leases(tmp_path):
    filename = tmp_path / "proxies.txt"
    filename.write_text("# comment\n\nsocks5://localhost:1080\n")
    pool = ProxyPool(str(filename))

    async def check():
        await asyncio.gather(pool.init(), pool.init())
        assert pool._proxies.qsize() == 1
        entered = asyncio.Event()

        async def lease():
            async with pool.get_proxy() as proxy:
                assert proxy == "socks5://localhost:1080"
                entered.set()
                await asyncio.Event().wait()

        task = asyncio.create_task(lease())
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        async with pool.get_proxy() as proxy:
            assert proxy == "socks5://localhost:1080"
        assert pool._proxies.qsize() == 1

    asyncio.run(check())


def test_empty_proxy_file_fails_instead_of_waiting_forever(tmp_path):
    filename = tmp_path / "proxies.txt"
    filename.write_text("\n# no proxies\n")
    with pytest.raises(ValueError, match="No proxies"):
        asyncio.run(ProxyPool(str(filename)).init())


def test_dashboard_navigation_preserves_children_for_each_page():
    manager = DashboardManager()
    root = manager.get_or_create_level()
    first = DashboardPage("First", root)
    second = DashboardPage("Second", root)
    root.add_page(first)
    root.add_page(second)
    first_child = manager.get_or_create_level(first)
    first_child.add_page(DashboardPage("First child", first_child))
    assert manager.navigate_up()
    assert manager.active_page is first
    assert manager.navigate_down()
    assert manager.active_level is first_child
    assert manager.navigate_up()
    assert manager.navigate_next()
    second_child = manager.get_or_create_level(second)
    second_child.add_page(DashboardPage("Second child", second_child))
    assert manager.navigate_up()
    assert manager.navigate_prev()
    assert manager.navigate_down()
    assert manager.active_level is first_child
    assert first_child is not second_child
    with pytest.raises(ValueError, match="positive"):
        manager.set_refresh_rate(0)


def test_encrypted_open_preserves_text_binary_and_file_descriptor_reads(tmp_path):
    # secure intentionally patches open globally; keep that behavior in a subprocess.
    script = """import builtins, os
from pathlib import Path
from w3plex import secure
source = Path("plain.txt")
source.write_text("hello\\n", encoding="utf-8")
encrypted = secure.encrypt_file(source, password="file password")
secure._all_keys = lambda: [secure._derive_file_key("file password")]
with builtins.open(encrypted) as stream:
    assert stream.read() == "hello\\n"
    assert stream.name == str(encrypted)
with builtins.open(encrypted, "rb") as stream:
    assert stream.read() == b"hello\\n"
descriptor = os.open(source, os.O_RDONLY)
with builtins.open(descriptor) as stream:
    assert stream.read() == "hello\\n"
assert secure._KEYSTORE_PATH == Path(os.environ["W3PLEX_KEYSTORE"])
"""
    import os

    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=tmp_path,
        env={**os.environ, "W3PLEX_KEYSTORE": str(tmp_path / "keystore.bin")},
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert result.returncode == 0, result.stderr
