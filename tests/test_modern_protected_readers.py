"""Modern encrypted inputs use existing configured readers and references."""

import asyncio
from functools import partial

import pytest
from eth_account import Account as EthAccount
from eth_account.messages import encode_defunct

from w3plex.config.reading import load_config, load_reference_config
from w3plex.runner import Runner
from w3plex.security import EncryptedIOContext, ISecretRef, LegacyContext, SecretJson
from w3plex.security import file_format as codec
from w3plex.security.errors import (
    AuthenticationFailed,
    InteractionRequired,
    InvalidStore,
    PermissionDenied,
)
from w3plex.utils.loader import FileLoader
from w3plex.w3 import Account

MASTER = b"PUBLIC-TEST-snapshot-password"
PASSWORD = "PUBLIC-TEST-modern-reader-password"
KEY = "11" * 32


@pytest.fixture
def context(secret_store):
    owner = EncryptedIOContext(
        protection=secret_store._vault.protection,
        keystore=secret_store._vault,
        input_handler=lambda _: PASSWORD,
    )
    try:
        yield owner
    finally:
        owner.close()


def encrypted(path, value):
    envelope, _ = codec.seal(value, PASSWORD.encode())
    raw = envelope.serialize()
    path.write_bytes(raw)
    return raw


def test_yaml_account_factory_restores_original_key_after_deletion(
    secret_store, context, tmp_path
):
    source = tmp_path / "keys.enc"
    original = encrypted(source, ("\ufeff# comment\r\n " + KEY + " \r\n").encode())
    config = tmp_path / "w3plex.yaml"
    config.write_text(
        "accounts:\n  main:\n    __init__: w3plex.utils.loader:accounts_loader\n"
        "    file: keys.enc\nalias: $accounts.main\n"
    )
    cfg = load_config(config, opener=context.open, environment={})
    assert cfg["accounts"]["main"]["file"] == "keys.enc"
    calls = []

    def opener(path):
        calls.append(path)
        return secret_store.capture_file(path, context=context)

    async def check():
        runner = Runner()
        await runner.init(cfg, str(config), file_opener=opener)
        try:
            account = (await runner.tree.accounts.main())[0]
            assert type(account) is Account and isinstance(account.key, ISecretRef)
            assert "_acc" not in vars(account) and KEY not in repr(vars(account))
            assert source.read_bytes() == original and len(calls) == 1
            secret_store._vault.lock()
            assert context._keys == {}
            context.lock()
            source.write_text("changed")
            source.unlink()
            with pytest.raises(PermissionDenied):
                await account.sign("public test message")
            secret_store._vault.unlock(MASTER)
            restored = (await runner.tree.alias())[0]
            signature = await restored.sign("public test message")
            assert (
                EthAccount.recover_message(
                    encode_defunct(text="public test message"), signature=signature
                )
                == account.address
            )
            assert restored.key.parent.identifier == account.key.parent.identifier
            assert len(calls) == 1
        finally:
            await runner.finalize()

    asyncio.run(check())


def test_relative_include_and_concurrent_reads_capture_once(
    secret_store, context, tmp_path
):
    nested = tmp_path / "nested"
    nested.mkdir()
    source = nested / "data.enc"
    encrypted(source, "\ufeff# comment\n α \n beta\n".encode())
    (tmp_path / "data.enc").write_text("wrong directory\n")
    (nested / "readers.yaml").write_text(
        "lines:\n  __init__: w3plex.utils.loader:FileLoader\n  file: data.enc\n"
    )
    config = tmp_path / "w3plex.yaml"
    config.write_text("readers: !include nested/readers.yaml\nalias: $readers.lines\n")
    cfg = load_config(config, opener=context.open, environment={})
    calls = []

    def opener(path):
        calls.append(path)
        return secret_store.capture_file(path, context=context)

    async def check():
        runner = Runner()
        await runner.init(cfg, str(config), file_opener=opener)
        try:
            first, second = await asyncio.gather(
                runner.tree.alias(), runner.tree.alias()
            )
            assert [value.ref(silent=True) for value in first] == ["α", "beta"]
            assert first[0].parent.identifier == second[0].parent.identifier
            assert len(calls) == 1 and str(source) == str(calls[0])
        finally:
            await runner.finalize()

    asyncio.run(check())


def test_modern_encrypted_yaml_uses_the_existing_parser(
    secret_store, context, tmp_path
):
    source = tmp_path / "w3plex.yaml"
    encrypted(
        source,
        b"object:\n  __init__: types:SimpleNamespace\n  label: example\nalias: $object\n",
    )
    reference = secret_store.capture_file(source, context=context)
    source.unlink()
    secret_store._vault.lock()
    context.lock()
    secret_store._vault.unlock(MASTER)
    cfg = load_reference_config(reference, filename=source, environment={})
    assert cfg.object["__init__"] == "types:SimpleNamespace" and cfg.alias == "$object"

    async def check():
        runner = Runner()
        await runner.init(cfg, str(source))
        try:
            assert runner.tree.object.label == "example"
            assert runner.tree.alias is runner.tree.object
        finally:
            await runner.finalize()

    asyncio.run(check())


def test_modern_json_child_restores_escaped_text(secret_store, context, tmp_path):
    source = tmp_path / "credentials.enc"
    encrypted(source, b'{"api":{"key":"PUBLIC-TEST-value\\n\\u03b1"}}')
    parent = secret_store.capture_file(source, context=context)
    child = SecretJson(parent, ("api", "key"))
    assert child.ref(silent=True) == "PUBLIC-TEST-value\nα"
    source.unlink()
    secret_store._vault.lock()
    context.lock()
    secret_store._vault.unlock(MASTER)
    assert child.ref(silent=True) == "PUBLIC-TEST-value\nα"


@pytest.mark.parametrize("value", [b"W3FILE2\n", b"W3VAULT1\n", b"W3FILE1\ninvalid"])
def test_invalid_format_cannot_fall_back_to_plain_capture(
    secret_store, context, tmp_path, value
):
    source = tmp_path / "data.enc"
    source.write_bytes(value)
    before = secret_store._vault.path.read_bytes()
    with pytest.raises(InvalidStore):
        secret_store.capture_file(source, context=context)
    assert secret_store._vault.path.read_bytes() == before


def test_failed_authentication_cannot_import_ciphertext_as_plaintext(
    secret_store, context, tmp_path
):
    source = tmp_path / "data.enc"
    encrypted(source, b"PUBLIC-TEST-secret")
    context._input = lambda _: "PUBLIC-TEST-wrong-password"
    reader = FileLoader(
        file=source, opener=partial(secret_store.capture_file, context=context)
    )
    before = secret_store._vault.path.read_bytes()
    with pytest.raises(AuthenticationFailed):
        asyncio.run(reader())
    assert secret_store._vault.path.read_bytes() == before and reader._source is None


def test_missing_context_requests_interaction_instead_of_capturing_ciphertext(
    secret_store, tmp_path
):
    source = tmp_path / "data.enc"
    encrypted(source, b"PUBLIC-TEST-secret")
    with pytest.raises(InteractionRequired):
        secret_store.capture_file(source)
    with pytest.raises(InteractionRequired):
        secret_store.capture_file(source, context=LegacyContext(None))


def test_protected_size_limit_precedes_password_input(
    secret_store, context, tmp_path, monkeypatch
):
    source = tmp_path / "large.enc"
    encrypted(source, b"PUBLIC-TEST-value")
    monkeypatch.setattr("w3plex.security.refs.MAX_SNAPSHOT_SIZE", 4)
    context._input = lambda _: pytest.fail("Oversized capture requested input")
    with pytest.raises(InvalidStore):
        secret_store.capture_file(source, context=context)
