"""phase5.ckpt1 #12 — POST /auth/password/reset (F7).

Validates an unused, unexpired reset token (matched by sha256 hash), sets a new
argon2 password_hash on the user, marks the token used, returns 204. A reused
(already-used) or expired token returns 400. An unknown token returns 400.

Same local-app harness as the other phase5 tests.
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
from app.models import PasswordReset, User
from app.routes.auth_reset import router
from app.security.hashing import hash_password, verify_password
from tests.test_migration import _async_test_url


def _hash(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


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


async def _make_user_with_token(factory, *, ttl_seconds=1800, used=False):
    """Create a user with a known old password and a reset token; return (email, raw_token)."""
    email = f"{uuid.uuid4().hex[:12]}@e.com"
    raw_token = uuid.uuid4().hex + uuid.uuid4().hex
    async with factory() as s:
        user = User(email=email, username=f"u-{uuid.uuid4().hex[:8]}",
                    password_hash=hash_password("OldPass1!"))
        s.add(user)
        await s.flush()
        s.add(PasswordReset(
            token_hash=_hash(raw_token),
            user_id=user.id,
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds),
            used=used,
        ))
        await s.commit()
    return email, raw_token


@pytest.mark.asyncio
async def test_reset_valid_token_sets_password_and_returns_204(client, factory):
    email, raw = await _make_user_with_token(factory)
    resp = await client.post("/auth/password/reset", json={"token": raw, "new_password": "BrandNew1!"})
    assert resp.status_code == 204
    async with factory() as s:
        user = (await s.execute(select(User).where(User.email == email))).scalar_one()
        row = (await s.execute(select(PasswordReset).where(PasswordReset.user_id == user.id))).scalar_one()
    # New password verifies, old one no longer does, token marked used.
    assert verify_password("BrandNew1!", user.password_hash)
    assert not verify_password("OldPass1!", user.password_hash)
    assert user.password_hash.startswith("$argon2")
    assert row.used is True


@pytest.mark.asyncio
async def test_reset_reused_token_returns_400(client, factory):
    email, raw = await _make_user_with_token(factory)
    first = await client.post("/auth/password/reset", json={"token": raw, "new_password": "BrandNew1!"})
    assert first.status_code == 204
    # Replaying the now-used token must fail.
    second = await client.post("/auth/password/reset", json={"token": raw, "new_password": "Another1!"})
    assert second.status_code == 400


@pytest.mark.asyncio
async def test_reset_expired_token_returns_400(client, factory):
    email, raw = await _make_user_with_token(factory, ttl_seconds=-1)  # already expired
    resp = await client.post("/auth/password/reset", json={"token": raw, "new_password": "BrandNew1!"})
    assert resp.status_code == 400
    # Password must be unchanged.
    async with factory() as s:
        user = (await s.execute(select(User).where(User.email == email))).scalar_one()
    assert verify_password("OldPass1!", user.password_hash)


@pytest.mark.asyncio
async def test_reset_already_used_token_returns_400(client, factory):
    email, raw = await _make_user_with_token(factory, used=True)
    resp = await client.post("/auth/password/reset", json={"token": raw, "new_password": "BrandNew1!"})
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_reset_unknown_token_returns_400(client):
    resp = await client.post("/auth/password/reset", json={"token": "no-such-token", "new_password": "X1!"})
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_concurrent_reset_consumes_token_exactly_once(factory):
    """#15 regression — single-use TOCTOU. A reset token must be consumable by
    EXACTLY ONE concurrent request. The old SELECT→check used→UPDATE let N
    concurrent resets all read used=false and all apply, consuming one single-use
    token N times (account-takeover surface).

    REAL cross-connection concurrency: a pooled engine gives each concurrent
    httpx request a DISTINCT postgres backend (in-process ASGITransport over one
    shared session is structurally blind to the race). Asserts exactly 1×204,
    N-1×400, ZERO 500s, and the password is applied (winner only).
    """
    N = 12
    email, raw = await _make_user_with_token(factory)

    # Pooled engine → distinct connections per concurrent request (real race).
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
            async def attempt():
                r = await ac.post(
                    "/auth/password/reset",
                    json={"token": raw, "new_password": "BrandNew1!"},
                )
                return r.status_code

            codes = await asyncio.gather(*[attempt() for _ in range(N)])
    finally:
        await engine.dispose()

    cnt = Counter(codes)
    assert cnt.get(500, 0) == 0, f"server error under concurrency (TOCTOU/deadlock leak): {dict(cnt)}"
    assert cnt.get(204, 0) == 1, f"single-use token consumed != once: {dict(cnt)}"
    assert cnt.get(400, 0) == N - 1, f"expected {N-1}×400, got {dict(cnt)}"

    # The winner's password change is applied exactly once and the token is burned.
    async with factory() as s:
        user = (await s.execute(select(User).where(User.email == email))).scalar_one()
        row = (await s.execute(select(PasswordReset).where(PasswordReset.user_id == user.id))).scalar_one()
    assert verify_password("BrandNew1!", user.password_hash)
    assert row.used is True
