"""Existing YAML account and address loaders use captured external data."""

import asyncio
import base64
import hashlib
from functools import partial

import pytest
from cryptography.fernet import Fernet
from eth_account import Account as EthAccount
from eth_account.messages import encode_defunct
from web3 import Web3

from w3plex.config.reading import load_config
from w3plex.runner import Runner
from w3plex.security import ISecretRef
from w3plex.security.errors import PermissionDenied, SecurityError
from w3plex.security.legacy import LegacyContext
from w3plex.utils.loader import accounts_loader
from w3plex.w3 import Account

KEY = "11" * 32
PASSWORD = b"PUBLIC-TEST-snapshot-password"
FILE_PASSWORD = "PUBLIC-TEST-reader-password"


def file_bytes(value, encrypted):
    if not encrypted:
        return value
    key = base64.urlsafe_b64encode(hashlib.sha256(FILE_PASSWORD.encode()).digest())
    return b"ENC1" + Fernet(key).encrypt(value)


@pytest.mark.parametrize("encrypted", [False, True])
def test_yaml_account_loader_keeps_snapshot_and_signs_after_unlock(
    secret_store, tmp_path, encrypted
):
    data = tmp_path / "keys.txt"
    original = file_bytes(("# comment\n " + KEY + " \n").encode(), encrypted)
    data.write_bytes(original)
    config = tmp_path / "w3plex.yaml"
    config.write_text(
        "accounts:\n"
        "  main:\n"
        "    __init__: w3plex.utils.loader:accounts_loader\n"
        "    file: keys.txt\n"
        "alias: $accounts.main\n"
    )
    cfg = load_config(config, opener=open, environment={})
    legacy = LegacyContext(None, input_handler=lambda request: FILE_PASSWORD)
    calls = []

    def opener(path):
        calls.append(path)
        return secret_store.capture_file(path, context=legacy)

    async def check():
        runner = Runner()
        await runner.init(cfg, str(config), file_opener=opener)
        try:
            account = (await runner.tree.accounts.main())[0]
            assert type(account) is Account
            assert isinstance(account.key, ISecretRef)
            assert "_acc" not in vars(account)
            assert KEY not in repr(vars(account))
            assert data.read_bytes() == original
            assert len(calls) == 1
            secret_store._vault.lock()
            legacy.lock()
            with pytest.raises(PermissionDenied):
                await runner.tree.alias()
            with pytest.raises(PermissionDenied):
                await account.sign("public message")
            data.write_text("changed private data\n")
            data.unlink()
            secret_store._vault.unlock(PASSWORD)
            restored = (await runner.tree.alias())[0]
            assert restored.address == account.address
            assert restored.key.parent.identifier == account.key.parent.identifier
            signature = await restored.sign("public message")
            assert (
                EthAccount.recover_message(
                    encode_defunct(text="public message"), signature=signature
                )
                == account.address
            )
            assert len(calls) == 1
        finally:
            await runner.finalize()
            legacy.lock()

    asyncio.run(check())


@pytest.mark.parametrize("encrypted", [False, True])
def test_existing_public_address_loader_returns_validated_strings(
    secret_store, tmp_path, encrypted
):
    address = "0x" + "12" * 20
    data = tmp_path / "wallets.txt"
    data.write_bytes(file_bytes((address + "\n").encode(), encrypted))
    config = tmp_path / "w3plex.yaml"
    config.write_text(
        "wallets:\n  __init__: w3plex.utils.loader:wallets_loader\n  file: wallets.txt\n"
    )
    cfg = load_config(config, opener=open, environment={})
    legacy = LegacyContext(None, input_handler=lambda request: FILE_PASSWORD)

    async def check():
        runner = Runner()
        await runner.init(
            cfg,
            str(config),
            file_opener=partial(secret_store.capture_file, context=legacy),
        )
        try:
            assert runner.tree.wallets == [Web3.to_checksum_address(address)]
            assert type(runner.tree.wallets[0]) is str
        finally:
            await runner.finalize()
            legacy.lock()

    asyncio.run(check())


@pytest.mark.parametrize("loader", ["accounts_loader", "wallets_loader"])
def test_invalid_protected_values_cannot_leak_through_reader_errors(
    secret_store, tmp_path, loader
):
    secret = "PUBLIC-TEST-invalid-private-value"
    data = tmp_path / "data.txt"
    data.write_text(secret + "\n")
    cfg = {"values": {"__init__": f"w3plex.utils.loader:{loader}", "file": str(data)}}

    async def check():
        runner = Runner()
        with pytest.raises(SecurityError) as caught:
            await runner.init(
                cfg,
                str(tmp_path / "w3plex.yaml"),
                file_opener=secret_store.capture_file,
            )
            await runner.tree["values"]()
        assert secret not in str(caught.value)
        assert caught.value.__cause__ is None
        assert caught.value.__context__ is None
        await runner.finalize()

    asyncio.run(check())


def test_existing_account_loader_accepts_a_reference_without_disclosure(secret_store):
    secret_store._confirm = lambda access: pytest.fail(
        "Unexpected plaintext disclosure"
    )
    source = secret_store.capture((KEY + "\n").encode())
    accounts = asyncio.run(accounts_loader(file=source)())
    assert type(accounts[0]) is Account
    assert isinstance(accounts[0].key, ISecretRef)
    assert accounts[0].address == EthAccount.from_key(KEY).address


def test_denied_source_use_never_constructs_a_signing_account(
    secret_store, monkeypatch
):
    source = secret_store.capture((KEY + "\n").encode())
    secret_store._vault.lock()
    monkeypatch.setattr(
        "w3plex.w3.account.EthAccount.from_key",
        lambda value: pytest.fail("Denied source reached the signing dependency"),
    )
    with pytest.raises(PermissionDenied):
        asyncio.run(accounts_loader(file=source)())
