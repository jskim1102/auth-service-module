"""phase3.ckpt2 #21 — refresh token rotation + reuse-detection (F4, security core).

Tokens are stored only as sha256 hashes (never plaintext). Rotation revokes the
old row and issues a new one in the same chain. Reusing a revoked token is treated
as theft: the WHOLE chain is revoked and the operation raises. A different chain
(another device) is left untouched — precise isolation (CTO option A).
"""
import asyncio
import hashlib
import uuid

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.db import make_engine
from app.models import RefreshToken, User
from app.refresh import issue_refresh, rotate_refresh, RefreshError
from tests.test_migration import _async_test_url


@pytest_asyncio.fixture
async def factory():
    # Expose the session factory so the concurrency test can give each parallel
    # task its OWN session (async sessions are not safe to share across tasks).
    # DB isolation is handled centrally by the autouse _clean_db fixture (conftest).
    engine = make_engine(_async_test_url())
    sf = async_sessionmaker(engine, expire_on_commit=False)
    yield sf
    await engine.dispose()


@pytest_asyncio.fixture
async def session(factory):
    async with factory() as s:
        yield s


@pytest_asyncio.fixture
async def user(session):
    # Unique email per test run so the users.email unique constraint never collides.
    u = User(email=f"u-{uuid.uuid4().hex[:12]}@e.com")
    session.add(u)
    await session.commit()
    await session.refresh(u)
    return u


async def _row_for(session, raw_token):
    h = hashlib.sha256(raw_token.encode()).hexdigest()
    return (
        await session.execute(select(RefreshToken).where(RefreshToken.token_hash == h))
    ).scalar_one_or_none()


@pytest.mark.asyncio
async def test_issue_stores_sha256_not_plaintext(session, user):
    raw = await issue_refresh(session, user.id)
    # Plaintext must never appear in the DB; only its sha256 hash.
    row = await _row_for(session, raw)
    assert row is not None
    assert row.token_hash == hashlib.sha256(raw.encode()).hexdigest()
    assert row.token_hash != raw
    plain = (
        await session.execute(select(RefreshToken).where(RefreshToken.token_hash == raw))
    ).scalar_one_or_none()
    assert plain is None


@pytest.mark.asyncio
async def test_rotate_revokes_old_issues_new_same_chain(session, user):
    raw1 = await issue_refresh(session, user.id)
    row1 = await _row_for(session, raw1)
    raw2 = await rotate_refresh(session, raw1)
    row1b = await _row_for(session, raw1)
    row2 = await _row_for(session, raw2)
    assert row1b.revoked is True            # old revoked
    assert row2.revoked is False            # new active
    assert row2.chain_id == row1.chain_id   # same rotation family
    assert raw2 != raw1


@pytest.mark.asyncio
async def test_reuse_of_revoked_revokes_whole_chain_and_raises(session, user):
    raw1 = await issue_refresh(session, user.id)
    chain_id = (await _row_for(session, raw1)).chain_id
    raw2 = await rotate_refresh(session, raw1)   # raw1 now revoked, raw2 active
    # Attacker replays the already-revoked raw1 → theft response.
    with pytest.raises(RefreshError):
        await rotate_refresh(session, raw1)
    # Entire chain (including the still-active raw2) must now be revoked.
    rows = (
        await session.execute(
            select(RefreshToken).where(RefreshToken.chain_id == chain_id)
        )
    ).scalars().all()
    assert all(r.revoked for r in rows)


@pytest.mark.asyncio
async def test_reuse_does_not_touch_other_chain(session, user):
    # Two independent logins = two chains. Compromising one must not revoke the other.
    raw_a1 = await issue_refresh(session, user.id)
    raw_b1 = await issue_refresh(session, user.id)
    chain_b = (await _row_for(session, raw_b1)).chain_id
    await rotate_refresh(session, raw_a1)
    with pytest.raises(RefreshError):
        await rotate_refresh(session, raw_a1)   # reuse on chain A
    rows_b = (
        await session.execute(
            select(RefreshToken).where(RefreshToken.chain_id == chain_b)
        )
    ).scalars().all()
    assert all(not r.revoked for r in rows_b)   # chain B untouched


@pytest.mark.asyncio
async def test_rotate_expired_token_raises(session, user):
    raw = await issue_refresh(session, user.id, ttl_seconds=-1)  # already expired
    with pytest.raises(RefreshError):
        await rotate_refresh(session, raw)


@pytest.mark.asyncio
async def test_concurrent_rotation_no_valid_children_explosion(factory, user):
    """Regression for the reviewer's TOCTOU race: N concurrent rotations of ONE
    valid token must NOT mint multiple valid children from a single parent.

    The atomic conditional UPDATE lets exactly one caller win; the losers see the
    parent already revoked and trigger the theft path (chain burn). Post-fix
    invariant: after ANY concurrent replay that raises RefreshError, ZERO active
    tokens remain in the chain. The atomic parent-revoke + successor-insert forces
    the loser's UPDATE to block on the winner's row lock; when the winner commits
    (successor included), the loser re-evaluates → 0 rows → reuse path burns the
    whole chain, revoking the winner's just-committed successor too. Net: 0 active.
    """
    async with factory() as s0:
        raw = await issue_refresh(s0, user.id)
        chain_id = (await _row_for(s0, raw)).chain_id

    async def rotate_once():
        # Each concurrent task gets its OWN session (async sessions aren't shareable).
        async with factory() as s:
            try:
                return await rotate_refresh(s, raw)
            except RefreshError as exc:
                return exc

    results = await asyncio.gather(*[rotate_once() for _ in range(8)])

    # (b) reuse-detection must have fired at least once under the concurrent storm.
    assert any(isinstance(r, RefreshError) for r in results)

    parent_hash = hashlib.sha256(raw.encode()).hexdigest()
    async with factory() as s:
        chain_rows = (
            await s.execute(select(RefreshToken).where(RefreshToken.chain_id == chain_id))
        ).scalars().all()
        active = [r for r in chain_rows if not r.revoked]
        active_children = [r for r in active if r.token_hash != parent_hash]
        # (a) NO valid-children explosion — the original 8-valid-children defect.
        # Post-fix invariant: the concurrent replay burns the chain, so the winner's
        # successor is revoked too — ZERO active children survive.
        assert len(active_children) == 0
        # (c) ZERO active tokens remain in the whole chain after the burn.
        assert len(active) == 0


@pytest.mark.asyncio
async def test_issue_refresh_commit_false_defers_persistence(factory, user):
    """Deterministic witness for the rotate-atomicity fix's mechanism (report #3).

    The fix fuses the parent-revoke and successor-insert into ONE transaction by
    giving issue_refresh a ``commit=False`` mode: the successor is flushed but NOT
    committed until rotate_refresh commits both together, so no other transaction
    can ever observe a committed successor without the committed parent-revoke.
    This pins that contract — with commit=False the new row is invisible to a
    SEPARATE connection (its own postgres backend) until the caller commits.

    Unlike test_concurrent_rotation_* (a weak in-process witness — cooperative
    asyncio always burns the successor, so it passes even on the buggy code), this
    is a hard RED→GREEN gate: pre-fix issue_refresh had no ``commit`` kwarg, so the
    call raises TypeError.
    """
    async with factory() as writer:
        raw = await issue_refresh(writer, user.id, commit=False)
        # Not committed yet → a separate connection (own backend) cannot see it.
        async with factory() as reader:
            assert await _row_for(reader, raw) is None
        await writer.commit()
    # After the caller commits, the successor is visible everywhere.
    async with factory() as reader:
        assert await _row_for(reader, raw) is not None
