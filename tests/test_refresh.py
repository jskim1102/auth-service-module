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
    parent already revoked and trigger the theft path (chain burn). We assert the
    SAFE invariants (CTO-corrected): no child explosion, reuse-detection fired, and
    at most one active token remains — NOT "exactly one" (the chain burn may revoke
    the winner's child too, which is acceptable for a security module).
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
        assert len(active_children) <= 1
        # (c) at most one active token in the whole chain.
        assert len(active) <= 1
