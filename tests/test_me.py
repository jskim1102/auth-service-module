"""phase7.ckpt1 ← F9 — GET /auth/me (Bearer-protected).

Valid Bearer access token → {id, email, username, identities}. identities is the
list of linked auth_identities providers (local + any SNS). Missing / malformed /
invalid / expired / tampered token → 401.
"""
import uuid

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.db import get_session, make_engine
from app.models import AuthIdentity, User
from app.routes.me import router
from app.tokens import issue_access
from tests.test_migration import _async_test_url


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


@pytest_asyncio.fixture
async def user_with_identities(factory):
    """A user with two linked identities (local + google)."""
    async with factory() as s:
        u = User(email=f"{uuid.uuid4().hex[:10]}@e.com", username=f"u-{uuid.uuid4().hex[:8]}",
                 password_hash="x")
        s.add(u)
        await s.flush()
        s.add(AuthIdentity(user_id=u.id, provider="local", provider_uid=u.email, email=u.email))
        s.add(AuthIdentity(user_id=u.id, provider="google", provider_uid="g-1", email=u.email))
        await s.commit()
        await s.refresh(u)
        return u


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_me_valid_bearer_returns_profile_with_identities(client, user_with_identities):
    token = issue_access(user_with_identities)
    resp = await client.get("/auth/me", headers=_bearer(token))
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == user_with_identities.id
    assert body["email"] == user_with_identities.email
    assert body["username"] == user_with_identities.username
    assert set(body["identities"]) == {"local", "google"}


@pytest.mark.asyncio
async def test_me_missing_token_401(client):
    resp = await client.get("/auth/me")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_me_malformed_header_401(client):
    resp = await client.get("/auth/me", headers={"Authorization": "NotBearer xyz"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_me_tampered_token_401(client, user_with_identities):
    token = issue_access(user_with_identities)
    tampered = token[:-3] + ("aaa" if not token.endswith("aaa") else "bbb")
    resp = await client.get("/auth/me", headers=_bearer(tampered))
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_me_garbage_token_401(client):
    resp = await client.get("/auth/me", headers=_bearer("not-a-jwt"))
    assert resp.status_code == 401
