"""phase4.ckpt2 #2 — POST /auth/login (F3).

identifier = username OR email, argon2-verified. On success returns
{access_token, refresh_token} in the body AND sets the SAME refresh as an
httpOnly cookie (both channels, user-confirmed). Bad creds → 401.

Same local-app harness as test_signup (get_session → TEST_DATABASE_URL).
"""
import uuid

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.db import get_session, make_engine
from app.models import User
from app.routes.auth_local import router
from app.security.hashing import hash_password
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
async def seeded_user(factory):
    """Insert a local user with a known argon2 password directly."""
    tag = uuid.uuid4().hex[:12]
    username = f"user-{tag}"
    email = f"{tag}@e.com"
    password = "S3cret-pass!"
    async with factory() as s:
        user = User(email=email, username=username, password_hash=hash_password(password))
        s.add(user)
        await s.commit()
    return {"username": username, "email": email, "password": password}


@pytest.mark.asyncio
async def test_login_by_username_returns_tokens(client, seeded_user):
    resp = await client.post(
        "/auth/login",
        json={"identifier": seeded_user["username"], "password": seeded_user["password"]},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["access_token"]
    assert body["refresh_token"]


@pytest.mark.asyncio
async def test_login_by_email_returns_tokens(client, seeded_user):
    resp = await client.post(
        "/auth/login",
        json={"identifier": seeded_user["email"], "password": seeded_user["password"]},
    )
    assert resp.status_code == 200
    assert resp.json()["access_token"]


@pytest.mark.asyncio
async def test_login_sets_httponly_refresh_cookie_equal_to_body(client, seeded_user):
    resp = await client.post(
        "/auth/login",
        json={"identifier": seeded_user["email"], "password": seeded_user["password"]},
    )
    assert resp.status_code == 200
    body_refresh = resp.json()["refresh_token"]
    # Cookie must be set, httpOnly, and carry the SAME value as the body refresh.
    set_cookie = resp.headers.get("set-cookie", "")
    assert "httponly" in set_cookie.lower()
    assert resp.cookies.get("refresh_token") == body_refresh


@pytest.mark.asyncio
async def test_login_refresh_cookie_secure_flag(client, seeded_user, monkeypatch):
    # #28 P1: COOKIE_SECURE=true → the refresh cookie carries Secure.
    monkeypatch.setenv("COOKIE_SECURE", "true")
    resp = await client.post(
        "/auth/login",
        json={"identifier": seeded_user["email"], "password": seeded_user["password"]},
    )
    assert "secure" in resp.headers.get("set-cookie", "").lower()


@pytest.mark.asyncio
async def test_login_refresh_cookie_secure_off_for_local_http(client, seeded_user, monkeypatch):
    # COOKIE_SECURE=false (local http dev) → Secure omitted.
    monkeypatch.setenv("COOKIE_SECURE", "false")
    resp = await client.post(
        "/auth/login",
        json={"identifier": seeded_user["email"], "password": seeded_user["password"]},
    )
    assert "secure" not in resp.headers.get("set-cookie", "").lower()


@pytest.mark.asyncio
async def test_login_access_token_verifies(client, seeded_user):
    resp = await client.post(
        "/auth/login",
        json={"identifier": seeded_user["email"], "password": seeded_user["password"]},
    )
    claims = verify_access(resp.json()["access_token"])
    assert claims["email"] == seeded_user["email"]


@pytest.mark.asyncio
async def test_login_bad_password_returns_401(client, seeded_user):
    resp = await client.post(
        "/auth/login",
        json={"identifier": seeded_user["email"], "password": "wrong-password"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_login_unknown_identifier_returns_401(client):
    resp = await client.post(
        "/auth/login",
        json={"identifier": "nobody@nowhere.com", "password": "whatever"},
    )
    assert resp.status_code == 401
