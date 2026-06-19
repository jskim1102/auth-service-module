"""phase6.ckpt1 ← F8 — POST /auth/oauth/exchange.

Exchanges the short-lived single-use one-time code (minted at callback) for
{access_token, refresh_token}, atomically consuming it. Reused or expired code →
400 with no token. Single-use must hold under concurrency (atomic consume).
"""
import asyncio
import hashlib
import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.db import get_session, make_engine
from app.models import OAuthCode, User
from app.routes.oauth import router
from app.tokens import verify_access
from tests.test_migration import _async_test_url


def _hash(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


@pytest_asyncio.fixture
async def factory():
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


async def _seed_code(factory, *, ttl=120, used=False):
    raw = uuid.uuid4().hex + uuid.uuid4().hex
    async with factory() as s:
        user = User(email=f"{uuid.uuid4().hex[:10]}@e.com")
        s.add(user)
        await s.flush()
        s.add(OAuthCode(
            code_hash=_hash(raw),
            user_id=user.id,
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=ttl),
            used=used,
        ))
        await s.commit()
        uid = user.id
    return raw, uid


@pytest.mark.asyncio
async def test_exchange_returns_tokens_and_consumes_code(client, factory):
    raw, uid = await _seed_code(factory)
    resp = await client.post("/auth/oauth/exchange", json={"code": raw})
    assert resp.status_code == 200
    body = resp.json()
    assert body["access_token"] and body["refresh_token"]
    assert verify_access(body["access_token"])["sub"] == str(uid)
    async with factory() as s:
        row = (await s.execute(select(OAuthCode).where(OAuthCode.code_hash == _hash(raw)))).scalar_one()
    assert row.used is True


@pytest.mark.asyncio
async def test_exchange_reused_code_returns_400(client, factory):
    raw, _ = await _seed_code(factory)
    first = await client.post("/auth/oauth/exchange", json={"code": raw})
    assert first.status_code == 200
    second = await client.post("/auth/oauth/exchange", json={"code": raw})
    assert second.status_code == 400


@pytest.mark.asyncio
async def test_exchange_expired_code_returns_400(client, factory):
    raw, _ = await _seed_code(factory, ttl=-1)
    resp = await client.post("/auth/oauth/exchange", json={"code": raw})
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_exchange_unknown_code_returns_400(client):
    resp = await client.post("/auth/oauth/exchange", json={"code": "no-such-code"})
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_concurrent_exchange_winner_gets_tokens_never_500(factory):
    """#17 — concurrent same-code exchange under REAL cross-connection load.

    The winner consumes the code AND must RECEIVE 200 + valid tokens (not be
    stranded by a NoResultFound→500 after the two-step consume-then-fetch). Every
    round: exactly 1×200 carrying a decodable access token, N-1×400, ZERO 500s.
    Multiple rounds because the transient miss is timing-dependent (the reviewer's
    4-worker probe caught it; raise the odds with rounds). Pooled engine = own
    postgres backend per request — in-process ASGITransport over one session is
    blind to it.
    """
    N, ROUNDS = 12, 6
    engine = create_async_engine(_async_test_url(), pool_size=N + 2, max_overflow=4)
    sf = async_sessionmaker(engine, expire_on_commit=False)
    app = FastAPI()
    app.include_router(router)

    async def _override_session():
        async with sf() as s:
            yield s

    app.dependency_overrides[get_session] = _override_session
    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            for rnd in range(ROUNDS):
                raw, uid = await _seed_code(factory)

                async def attempt():
                    r = await ac.post("/auth/oauth/exchange", json={"code": raw})
                    return r.status_code, (r.json() if r.status_code == 200 else None)

                results = await asyncio.gather(*[attempt() for _ in range(N)])
                cnt = Counter(s for s, _ in results)
                assert cnt.get(500, 0) == 0, f"round {rnd}: 500 under concurrency: {dict(cnt)}"
                assert cnt.get(200, 0) == 1, f"round {rnd}: winners != 1: {dict(cnt)}"
                assert cnt.get(400, 0) == N - 1, f"round {rnd}: expected {N-1}×400: {dict(cnt)}"
                # The single winner must carry VALID tokens for the right user.
                winner_body = next(body for s, body in results if s == 200)
                assert winner_body["access_token"] and winner_body["refresh_token"]
                assert verify_access(winner_body["access_token"])["sub"] == str(uid)
    finally:
        await engine.dispose()
