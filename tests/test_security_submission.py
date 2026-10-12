"""Journal acknowledgment and cancellation at transaction submission boundaries."""

import asyncio

import pytest
from test_security_signing import setup

from w3plex.security.errors import PermissionDenied, SecurityError
from w3plex.security.signing import SubmissionState


async def signed_transaction(signer, chain, wallet):
    intent = await signer.prepare_transaction(
        chain, wallet, {"gas": 21000, "to": "0x" + "22" * 20}, operation="submission"
    )
    return signer.sign_transaction(intent, await signer.authorize(intent))


@pytest.mark.parametrize("ack", [False, None, 1, "exception"])
def test_failed_presend_acknowledgment_prevents_broadcast(tmp_path, ack, monkeypatch):
    async def check():
        session, wallet, provider, chain, _authorizer, journal, signer = await setup(
            tmp_path
        )
        signed = await signed_transaction(signer, chain, wallet)

        async def commit(record, raw):
            assert record.state is SubmissionState.PREPARED
            assert (
                record.operation == "submission"
                and record.request_identity == signed.intent.identity
            )
            assert (
                record.transaction_hash == signed.transaction_hash and raw == signed.raw
            )
            if ack == "exception":
                raise OSError("PUBLIC-TEST-private-journal-detail")
            return ack

        monkeypatch.setattr(journal, "commit", commit)
        with pytest.raises(SecurityError) as raised:
            await signer.submit(chain, signed)
        assert "PUBLIC-TEST-private" not in str(raised.value)
        assert raised.value.__cause__ is None and raised.value.__context__ is None
        assert provider.raw == []
        with pytest.raises(PermissionDenied):
            await signer.submit(chain, signed)
        await session.close()

    asyncio.run(check())


@pytest.mark.parametrize("ack", [False, None, 1, "exception"])
def test_postsend_journal_failure_returns_same_uncertain_hash(
    tmp_path, ack, monkeypatch
):
    async def check():
        session, wallet, provider, chain, authorizer, journal, signer = await setup(
            tmp_path
        )
        signed = await signed_transaction(signer, chain, wallet)
        original = journal.commit

        async def commit(record, raw):
            if record.state is SubmissionState.PREPARED:
                return await original(record, raw)
            if ack == "exception":
                raise OSError("PUBLIC-TEST-private-journal-detail")
            return ack

        monkeypatch.setattr(journal, "commit", commit)
        result = await signer.submit(chain, signed)
        assert result.state is SubmissionState.UNCERTAIN
        assert result.transaction_hash == signed.transaction_hash
        assert len(provider.raw) == 1 and len(authorizer.requests) == 1
        assert journal.records[0][0].state is SubmissionState.PREPARED
        assert journal.records[0][1] == signed.raw
        await session.close()

    asyncio.run(check())


@pytest.mark.parametrize("ignore_cancel", [False, True])
def test_lock_during_presend_commit_prevents_late_broadcast(
    tmp_path, ignore_cancel, monkeypatch
):
    async def check():
        session, wallet, provider, chain, _authorizer, journal, signer = await setup(
            tmp_path
        )
        signed = await signed_transaction(signer, chain, wallet)
        reached = asyncio.Event()

        async def commit(record, raw):
            reached.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                if not ignore_cancel:
                    raise
                # Model a dependency that committed before noticing cancellation.
                journal.records.append((record, raw))
                return True

        monkeypatch.setattr(journal, "commit", commit)
        task = asyncio.create_task(signer.submit(chain, signed))
        await asyncio.wait_for(reached.wait(), timeout=5)
        await session.lock()
        with pytest.raises(
            PermissionDenied if ignore_cancel else asyncio.CancelledError
        ):
            await task
        assert provider.raw == [] and provider.closed
        await session.close()

    asyncio.run(check())


def test_lock_after_broadcast_keeps_durable_uncertain_state(tmp_path, monkeypatch):
    async def check():
        session, wallet, provider, chain, _authorizer, journal, signer = await setup(
            tmp_path
        )
        signed = await signed_transaction(signer, chain, wallet)
        reached = asyncio.Event()
        original = chain.send_raw_transaction

        async def request(raw):
            response = await original(raw)
            reached.set()
            await asyncio.Event().wait()
            return response

        monkeypatch.setattr(chain, "send_raw_transaction", request)
        task = asyncio.create_task(signer.submit(chain, signed))
        await asyncio.wait_for(reached.wait(), timeout=5)
        await session.lock()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert len(provider.raw) == 1 and provider.closed
        assert [record.state for record, _ in journal.records] == [
            SubmissionState.PREPARED,
            SubmissionState.UNCERTAIN,
        ]
        assert all(
            record.transaction_hash == signed.transaction_hash and raw == signed.raw
            for record, raw in journal.records
        )
        assert signer._signed == {} and signer._permits == {}
        await session.close()

    asyncio.run(check())
