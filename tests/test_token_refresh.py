"""phase4.ckpt3 #4 — POST /auth/token/refresh (F5).

Accepts the refresh from the httpOnly cookie OR the request body (body wins if
both present, user-confirmed). Rotates via app.refresh.rotate_refresh (the
atomic #22 reuse-detection path — one call per request, no pre-SELECT), returns
new {access_token, refresh_token} in the body AND the rotated refresh as an
httpOnly cookie. Expired/revoked → 401; reuse of a revoked token triggers the
whole-chain burn (F4) and → 401.
"""
import asyncio
import uuid

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.db import get_session, make_engine
from app.models import RefreshToken, User
from app.refresh import RefreshError, _hash, issue_refresh, rotate_refresh
from app.routes.auth_token import router
from app.tokens import verify_access
from tests.test_migration import _async_test_url


@pytest_asyncio.fixture
async def factory():
    # DB isolation is handled centrally by the autouse _clean_db fixture (conftest).
    engine = make_engine(_async_test_url())
    sf = async_sessionmaker(engine, expire_on_commit=False)
    yield sf
    await engine.dispose()


@pytest_asyncio.fixture
async def client(factory):
    app = FastAPI()
    app.include_router(router)

    async def _override_session():
        async with factory() as s:
            yield s

    app.dependency_overrides[get_session] = _override_session
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest_asyncio.fixture
async def user(factory):
    async with factory() as s:
        u = User(email=f"{uuid.uuid4().hex[:12]}@e.com")
        s.add(u)
        await s.commit()
        await s.refresh(u)
        return u


async def _row(factory, raw):
    async with factory() as s:
        return (
            await s.execute(
                select(RefreshToken).where(RefreshToken.token_hash == _hash(raw))
            )
        ).scalar_one_or_none()


@pytest.mark.asyncio
async def test_refresh_from_body_returns_new_tokens(client, factory, user):
    async with factory() as s:
        raw = await issue_refresh(s, user.id)
    resp = await client.post("/auth/token/refresh", json={"refresh_token": raw})
    assert resp.status_code == 200
    body = resp.json()
    assert body["access_token"]
    assert body["refresh_token"]
    assert body["refresh_token"] != raw  # rotated to a new token


@pytest.mark.asyncio
async def test_refresh_rotated_cookie_equals_body_and_httponly(client, factory, user):
    async with factory() as s:
        raw = await issue_refresh(s, user.id)
    resp = await client.post("/auth/token/refresh", json={"refresh_token": raw})
    body_refresh = resp.json()["refresh_token"]
    set_cookie = resp.headers.get("set-cookie", "")
    assert "httponly" in set_cookie.lower()
    assert resp.cookies.get("refresh_token") == body_refresh


@pytest.mark.asyncio
async def test_refresh_from_cookie_when_no_body(client, factory, user):
    async with factory() as s:
        raw = await issue_refresh(s, user.id)
    client.cookies.set("refresh_token", raw)  # set on client (per-request is deprecated)
    resp = await client.post("/auth/token/refresh", json={})
    assert resp.status_code == 200
    assert resp.json()["access_token"]


@pytest.mark.asyncio
async def test_refresh_access_token_belongs_to_user(client, factory, user):
    async with factory() as s:
        raw = await issue_refresh(s, user.id)
    resp = await client.post("/auth/token/refresh", json={"refresh_token": raw})
    claims = verify_access(resp.json()["access_token"])
    assert claims["sub"] == str(user.id)


@pytest.mark.asyncio
async def test_refresh_old_token_now_revoked(client, factory, user):
    async with factory() as s:
        raw = await issue_refresh(s, user.id)
    await client.post("/auth/token/refresh", json={"refresh_token": raw})
    old = await _row(factory, raw)
    assert old.revoked is True


@pytest.mark.asyncio
async def test_refresh_expired_returns_401(client, factory, user):
    async with factory() as s:
        raw = await issue_refresh(s, user.id, ttl_seconds=-1)  # already expired
    resp = await client.post("/auth/token/refresh", json={"refresh_token": raw})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_refresh_reuse_returns_401_and_burns_chain(client, factory, user):
    async with factory() as s:
        raw = await issue_refresh(s, user.id)
        chain_id = (
            await s.execute(
                select(RefreshToken.chain_id).where(RefreshToken.token_hash == _hash(raw))
            )
        ).scalar_one()
    # First rotation succeeds, raw is now revoked, a child exists in the chain.
    first = await client.post("/auth/token/refresh", json={"refresh_token": raw})
    assert first.status_code == 200
    # Replaying the revoked raw → reuse/theft: 401 AND the whole chain is burned.
    reuse = await client.post("/auth/token/refresh", json={"refresh_token": raw})
    assert reuse.status_code == 401
    async with factory() as s:
        rows = (
            await s.execute(
                select(RefreshToken).where(RefreshToken.chain_id == chain_id)
            )
        ).scalars().all()
    assert rows  # chain exists
    assert all(r.revoked for r in rows)  # whole chain revoked (F4)


@pytest.mark.asyncio
async def test_refresh_no_token_at_all_returns_401(client):
    resp = await client.post("/auth/token/refresh", json={})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_concurrent_reuse_burn_never_raises_dbapi_deadlock(factory, user):
    """#10 regression — chain-burn under concurrent reuse must surface as the
    contractual RefreshError (→401), NEVER a raw DBAPIError/DeadlockDetectedError
    (→500). F5 says reuse→401.

    REAL cross-connection concurrency: each gather task gets its OWN session
    (= its own postgres backend), so the chain-wide `UPDATE ... WHERE chain_id`
    in _revoke_chain can interleave row-lock acquisition across backends and
    deadlock. In-process ASGITransport cannot surface this (one event loop,
    serialized) — the reviewer caught it only on a multi-worker uvicorn. Several
    rounds because a deadlock is timing-dependent (reviewer saw ~1/10).

    Pre-fix: at least one task raises a bare DBAPIError (the asyncpg deadlock) →
    this test fails. Post-fix: the burn is retried/falls back to RefreshError, so
    every reuse result is a RefreshError and zero DBAPIErrors escape.
    """
    ROUNDS, FANOUT = 10, 12
    for _ in range(ROUNDS):
        # Fresh chain each round: one parent + several rotated children, then the
        # parent is revoked so every replay below is "reuse of a revoked token".
        async with factory() as s:
            raw = await issue_refresh(s, user.id)
            chain_id = (
                await s.execute(
                    select(RefreshToken.chain_id).where(RefreshToken.token_hash == _hash(raw))
                )
            ).scalar_one()
            # Several siblings so the chain-burn UPDATE touches multiple rows
            # (single-row burns can't deadlock the way the multi-row one does).
            for _ in range(5):
                await issue_refresh(s, user.id, chain_id=chain_id)
        # First rotation revokes `raw`; now every concurrent replay is reuse.
        async with factory() as s0:
            await rotate_refresh(s0, raw)

        async def replay_reuse():
            async with factory() as s:  # own connection
                try:
                    await rotate_refresh(s, raw)
                    return "rotated"  # should never happen for a revoked token
                except RefreshError:
                    return "refresh_error"  # the contractual reuse signal (→401)
                except DBAPIError as exc:
                    # A leaked deadlock/serialization error = the #10 defect (→500).
                    return f"dbapi:{getattr(exc.orig, 'sqlstate', '?')}"

        results = await asyncio.gather(*[replay_reuse() for _ in range(FANOUT)])
        leaked = [r for r in results if isinstance(r, str) and r.startswith("dbapi:")]
        assert not leaked, f"deadlock/serialization error leaked (→500 not 401): {leaked}"
        # Reuse must never mint a valid child.
        assert "rotated" not in results
        # And the chain must end fully revoked (idempotent burn completed).
        async with factory() as s:
            rows = (
                await s.execute(
                    select(RefreshToken).where(RefreshToken.chain_id == chain_id)
                )
            ).scalars().all()
        assert all(r.revoked for r in rows)
