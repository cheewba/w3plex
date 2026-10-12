"""Private imports commit once and leave synthetic source files unchanged."""

import asyncio
import base64
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from eth_account import Account
from test_security_interaction_session import make_session, pending, unlock

from w3plex.security.contracts import SecretKind, SecretUse
from w3plex.security.errors import AuthenticationFailed, PermissionDenied, SecurityError
from w3plex.security.importing import LegacyImporter
from w3plex.security.interaction import PrivateReply

FIXTURES = Path(__file__).parent / "fixtures/legacy-security"


async def respond(private, task, *, approve=lambda request: True, password=None):
    steps = []
    manifest = json.loads((FIXTURES / "manifest.json").read_text())
    for _ in range(200):
        if task.done():
            break
        for request in private.control_port().pending():
            steps.append(request.step)
            values = {
                field.name: (
                    (password if password is not None else manifest["master_password"])
                    if request.step.startswith("legacy-master")
                    else manifest["file_password"]
                )
                if field.name == "password"
                else approve(request)
                for field in request.fields
            }
            private.control_port().answer(
                PrivateReply(
                    request.operation, request.step, request.identifier, values
                )
            )
        await asyncio.sleep(0)
    if not task.done():
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        raise AssertionError("Import did not finish")
    return await task, steps


@pytest.mark.parametrize("n", [4096, 8192, 16384, 32768])
def test_ks01_imports_file_keys_without_turning_them_into_wallets(tmp_path, n):
    async def check():
        session, private, _ = make_session(tmp_path)
        await unlock(session, private)
        source = tmp_path / "legacy"
        original = (FIXTURES / f"ks01-{n}.bin").read_bytes()
        source.write_bytes(original)
        importer = LegacyImporter(session._vault, session, private_input=private)
        operation = private.begin_operation()
        task = asyncio.create_task(
            importer.import_source(
                source, operation=operation, kind=SecretKind.LEGACY_FILE_KEY
            )
        )
        result, steps = await respond(private, task)
        assert len(result) == 1
        assert result[0].kind is SecretKind.LEGACY_FILE_KEY
        assert result[0].address is None
        assert steps == ["legacy-source", "legacy-master-0", "legacy-commit"]
        manifest = json.loads((FIXTURES / "manifest.json").read_text())
        expected = hashlib.sha256(manifest["file_password"].encode()).digest()
        assert session._vault._use_secret(
            result[0], SecretUse.DECRYPT, lambda value: value == expected
        )
        with pytest.raises(PermissionDenied):
            session._vault._use_secret(
                result[0], SecretUse.TRANSACTION, lambda value: value
            )
        assert source.read_bytes() == original
        await session.close()

    asyncio.run(check())


@pytest.mark.parametrize(
    "variant", ["wrong-password", "unsupported-n", "damaged-token"]
)
def test_keystore_authentication_failure_preserves_existing_destination(
    tmp_path, variant
):
    async def check():
        session, private, _ = make_session(tmp_path)
        generation = await unlock(session, private)
        previous = session.use(
            generation,
            "existing-import",
            lambda: session._vault.import_records(
                [(SecretKind.API, b"PUBLIC-TEST-existing-key", (SecretUse.HTTP,))]
            ),
        )
        manifest = json.loads((FIXTURES / "manifest.json").read_text())
        raw = (FIXTURES / "ks01-4096.bin").read_bytes()
        if variant == "unsupported-n":
            salt = b"PUBLIC-TEST-salt"
            key = hashlib.scrypt(
                manifest["master_password"].encode(),
                salt=salt,
                n=2048,
                r=8,
                p=1,
                dklen=32,
            )
            raw = (
                salt
                + b"KS01"
                + Fernet(base64.urlsafe_b64encode(key)).encrypt(
                    json.dumps(
                        {"keys": [base64.b64encode(b"x" * 32).decode()]}
                    ).encode()
                )
            )
        elif variant == "damaged-token":
            raw = raw[:20] + b"damaged-public-test-token"
        source = tmp_path / "legacy"
        source.write_bytes(raw)
        before = session._vault._storage.read()[0]
        importer = LegacyImporter(session._vault, session, private_input=private)
        task = asyncio.create_task(
            importer.import_source(
                source,
                operation=private.begin_operation(),
                kind=SecretKind.LEGACY_FILE_KEY,
            )
        )
        with pytest.raises(AuthenticationFailed) as raised:
            await respond(
                private,
                task,
                password="PUBLIC-TEST-wrong" if variant == "wrong-password" else None,
            )
        assert str(raised.value) == "authentication_failed"
        assert raised.value.__cause__ is None and raised.value.__context__ is None
        assert source.read_bytes() == raw
        assert session._vault._storage.read()[0] == before
        assert session._vault.references() == previous
        await session.close()

    asyncio.run(check())


@pytest.mark.parametrize(
    "kind",
    [
        SecretKind.API,
        SecretKind.RPC,
        SecretKind.MODEL,
        SecretKind.SEED,
        SecretKind.PASSWORD,
    ],
)
def test_plaintext_import_keeps_each_secret_kind_and_allowed_use(tmp_path, kind):
    async def check():
        session, private, _ = make_session(tmp_path)
        generation = await unlock(session, private)
        value = b"PUBLIC-TEST-private-import-value"
        source = tmp_path / "selected"
        source.write_bytes(value)
        importer = LegacyImporter(session._vault, session, private_input=private)
        task = asyncio.create_task(
            importer.import_source(
                source, operation=private.begin_operation(), kind=kind
            )
        )
        result, steps = await respond(private, task)
        assert steps == ["legacy-source", "legacy-commit"]
        use = (
            SecretUse.HTTP
            if kind in {SecretKind.API, SecretKind.RPC, SecretKind.MODEL}
            else SecretUse.RECOVERY
        )
        assert session.use(
            generation,
            "verify",
            lambda: session._vault._use_secret(
                result[0], use, lambda secret: secret == value
            ),
        )
        assert result[0].kind is kind and result[0].address is None
        assert value.decode() not in repr(result)
        assert source.read_bytes() == value
        assert all(
            value not in file.read_bytes() for file in (tmp_path / "secrets").iterdir()
        )
        await session.close()

    asyncio.run(check())


@pytest.mark.parametrize(
    "content", [b"", b"01" * 32 + b"\nnot-a-key", b"02" * 31, b"00" * 32]
)
def test_wallet_input_validates_all_records_before_any_write(tmp_path, content):
    async def check():
        session, private, _ = make_session(tmp_path)
        await unlock(session, private)
        source = tmp_path / "wallets"
        source.write_bytes(content)
        before = session._vault._storage.read()[0]
        importer = LegacyImporter(session._vault, session, private_input=private)
        task = asyncio.create_task(
            importer.import_source(
                source, operation=private.begin_operation(), kind=SecretKind.WALLET
            )
        )
        with pytest.raises(SecurityError):
            await respond(private, task)
        assert session._vault._storage.read()[0] == before
        assert source.read_bytes() == content
        await session.close()

    asyncio.run(check())


@pytest.mark.parametrize("step", ["legacy-master-0", "legacy-commit"])
def test_lock_during_private_import_cancels_task_and_keeps_destination(tmp_path, step):
    async def check():
        session, private, _ = make_session(tmp_path)
        await unlock(session, private)
        source = tmp_path / "legacy"
        original = (FIXTURES / "ks01-4096.bin").read_bytes()
        source.write_bytes(original)
        before = session._vault._storage.read()[0]
        importer = LegacyImporter(session._vault, session, private_input=private)
        task = asyncio.create_task(
            importer.import_source(
                source,
                operation=private.begin_operation(),
                kind=SecretKind.LEGACY_FILE_KEY,
            )
        )
        request = await pending(private.control_port())
        private.control_port().answer(
            PrivateReply(
                request.operation, request.step, request.identifier, {"confirm": True}
            )
        )
        request = await pending(private.control_port())
        if step == "legacy-commit":
            manifest = json.loads((FIXTURES / "manifest.json").read_text())
            private.control_port().answer(
                PrivateReply(
                    request.operation,
                    request.step,
                    request.identifier,
                    {"password": manifest["master_password"]},
                )
            )
            request = await pending(private.control_port())
        assert request.step == step
        await session.lock()
        with pytest.raises(asyncio.CancelledError):
            await task
        with pytest.raises(PermissionDenied):
            private.control_port().answer(
                PrivateReply(
                    request.operation,
                    request.step,
                    request.identifier,
                    {"confirm": True},
                )
            )
        assert session._vault._storage.read()[0] == before
        assert source.read_bytes() == original
        await session.close()

    asyncio.run(check())


@pytest.mark.parametrize("action", ["success", "cancel", "change", "wrong-address"])
def test_enc1_wallet_import_binds_both_sources_and_commits_only_complete_data(
    tmp_path, action
):
    async def check():
        session, private, _ = make_session(tmp_path)
        await unlock(session, private)
        manifest = json.loads((FIXTURES / "manifest.json").read_text())
        key = bytes.fromhex("01" * 32)
        file_key = hashlib.sha256(manifest["file_password"].encode()).digest()
        source = tmp_path / "wallets.enc"
        original = b"ENC1" + Fernet(base64.urlsafe_b64encode(file_key)).encrypt(
            (key.hex() + "\n").encode()
        )
        source.write_bytes(original)
        keystore = tmp_path / "keystore"
        keystore_original = (FIXTURES / "ks01-4096.bin").read_bytes()
        keystore.write_bytes(keystore_original)
        destination_before = session._vault._storage.read()[0]
        importer = LegacyImporter(session._vault, session, private_input=private)
        operation = private.begin_operation()
        expected = (
            (Account.from_key(key).address,)
            if action != "wrong-address"
            else ("0x" + "22" * 20,)
        )
        task = asyncio.create_task(
            importer.import_source(
                source,
                operation=operation,
                kind=SecretKind.WALLET,
                legacy_keystore=keystore,
                expected_addresses=expected,
            )
        )

        def approve(request):
            if request.step == "legacy-commit":
                if action == "cancel":
                    return False
                if action == "change":
                    keystore.write_bytes(b"changed")
            return True

        if action == "success":
            result, steps = await respond(private, task, approve=approve)
            assert result[0].address == expected[0]
            assert "legacy-keystore" in steps
            assert session._vault.references() == result
        else:
            with pytest.raises(SecurityError):
                await respond(private, task, approve=approve)
            assert session._vault._storage.read()[0] == destination_before
            assert session._vault.references() == ()
        assert source.read_bytes() == original
        if action != "change":
            assert keystore.read_bytes() == keystore_original
        await session.close()

    asyncio.run(check())


def test_damaged_legacy_store_is_not_successful_empty_import(tmp_path):
    async def check():
        session, private, _ = make_session(tmp_path)
        await unlock(session, private)
        source = tmp_path / "damaged"
        source.write_bytes(b"s" * 16 + b"not-json")
        before = session._vault._storage.read()[0]
        importer = LegacyImporter(session._vault, session, private_input=private)
        task = asyncio.create_task(
            importer.import_source(
                source,
                operation=private.begin_operation(),
                kind=SecretKind.LEGACY_FILE_KEY,
            )
        )
        with pytest.raises(SecurityError) as raised:
            await respond(private, task)
        assert raised.value.__cause__ is None and raised.value.__context__ is None
        assert session._vault._storage.read()[0] == before
        assert source.read_bytes() == b"s" * 16 + b"not-json"
        await session.close()

    asyncio.run(check())
