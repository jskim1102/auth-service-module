"""phase4.ckpt2 #3 — POST /auth/logout (F6).

Revokes the presented refresh token's row and returns 204. Idempotent:
already-revoked and unknown tokens also return 204 (no enumeration,
CTO-confirmed).

SECURITY DISTINCTION (load-bearing): logout's revoke is a PLAIN idempotent
revoke of ONLY the presented row — it must NEVER burn the whole chain. Chain
burning is reserved for rotate_refresh on REUSE of a revoked token (#4). A
benign logout / double-logout must leave the rest of the rotation family alone,
otherwise logging out one device would self-DoS the others.
"""
import uuid

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.db import get_session, make_engine
from app.models import RefreshToken, User
from app.refresh import _hash, issue_refresh
from app.routes.auth_local import router
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
async def test_logout_revokes_and_returns_204(client, factory, user):
    async with factory() as s:
        raw = await issue_refresh(s, user.id)
    resp = await client.post("/auth/logout", json={"refresh_token": raw})
    assert resp.status_code == 204
    row = await _row(factory, raw)
    assert row.revoked is True


@pytest.mark.asyncio
async def test_logout_already_revoked_still_204(client, factory, user):
    async with factory() as s:
        raw = await issue_refresh(s, user.id)
    first = await client.post("/auth/logout", json={"refresh_token": raw})
    assert first.status_code == 204
    second = await client.post("/auth/logout", json={"refresh_token": raw})
    assert second.status_code == 204


@pytest.mark.asyncio
async def test_logout_unknown_token_still_204(client):
    resp = await client.post("/auth/logout", json={"refresh_token": "not-a-real-token"})
    assert resp.status_code == 204


@pytest.mark.asyncio
async def test_logout_does_not_burn_chain(client, factory, user):
    # One chain, two live tokens (a rotation produced a sibling). Logging out one
    # must NOT revoke the sibling — only chain-burn (reuse path) may do that.
    async with factory() as s:
        raw1 = await issue_refresh(s, user.id)
        chain_id = (
            await s.execute(
                select(RefreshToken.chain_id).where(
                    RefreshToken.token_hash == _hash(raw1)
                )
            )
        ).scalar_one()
        raw2 = await issue_refresh(s, user.id, chain_id=chain_id)  # sibling, same chain

    resp = await client.post("/auth/logout", json={"refresh_token": raw1})
    assert resp.status_code == 204

    row1 = await _row(factory, raw1)
    row2 = await _row(factory, raw2)
    assert row1.revoked is True       # the logged-out token revoked
    assert row2.revoked is False      # sibling in same chain UNTOUCHED (no chain burn)


@pytest.mark.asyncio
async def test_logout_from_cookie_revokes_with_empty_body(client, factory, user):
    # #28 P1: the browser holds the refresh in the httpOnly cookie and POSTs {}.
    # logout must read the cookie (not require a body) → revoke → 204.
    async with factory() as s:
        raw = await issue_refresh(s, user.id)
    client.cookies.set("refresh_token", raw)
    resp = await client.post("/auth/logout", json={})  # empty body; cookie carries refresh
    assert resp.status_code == 204
    row = await _row(factory, raw)
    assert row.revoked is True


@pytest.mark.asyncio
async def test_logout_no_cookie_no_body_still_204(client):
    # No refresh anywhere → still 204 (idempotent, no enumeration), not 422.
    resp = await client.post("/auth/logout", json={})
    assert resp.status_code == 204
