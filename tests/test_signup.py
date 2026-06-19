"""phase4.ckpt1 #1 — POST /auth/signup (F2).

argon2-hashed local signup: inserts users + auth_identities(provider=local),
returns 201. Stored password_hash must start with $argon2 and never equal the
plaintext. Duplicate email or username → 409.

Test harness (CTO-approved): a per-module local FastAPI app mounts only the
router under test and overrides get_session → TEST_DATABASE_URL (option A).
app/main.py is NOT touched here (that is phase8.ckpt2). Unique emails/usernames
per test so the persistent test postgres never collides across runs.
"""
import uuid

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.db import get_session, make_engine
from app.models import AuthIdentity, User
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


def _creds():
    tag = uuid.uuid4().hex[:12]
    return {"username": f"user-{tag}", "email": f"{tag}@e.com", "password": "S3cret-pass!"}


@pytest.mark.asyncio
async def test_signup_returns_201(client):
    resp = await client.post("/auth/signup", json=_creds())
    assert resp.status_code == 201


@pytest.mark.asyncio
async def test_signup_stores_argon2_hash_not_plaintext(client, factory):
    creds = _creds()
    resp = await client.post("/auth/signup", json=creds)
    assert resp.status_code == 201
    async with factory() as s:
        user = (
            await s.execute(select(User).where(User.email == creds["email"]))
        ).scalar_one()
    assert user.password_hash.startswith("$argon2")
    assert user.password_hash != creds["password"]


@pytest.mark.asyncio
async def test_signup_creates_local_identity(client, factory):
    creds = _creds()
    await client.post("/auth/signup", json=creds)
    async with factory() as s:
        user = (
            await s.execute(select(User).where(User.email == creds["email"]))
        ).scalar_one()
        identity = (
            await s.execute(
                select(AuthIdentity).where(AuthIdentity.user_id == user.id)
            )
        ).scalar_one()
    assert identity.provider == "local"


@pytest.mark.asyncio
async def test_signup_duplicate_email_returns_409(client):
    creds = _creds()
    first = await client.post("/auth/signup", json=creds)
    assert first.status_code == 201
    dup = dict(creds, username=f"user-{uuid.uuid4().hex[:12]}")  # same email, new username
    resp = await client.post("/auth/signup", json=dup)
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_signup_duplicate_username_returns_409(client):
    creds = _creds()
    first = await client.post("/auth/signup", json=creds)
    assert first.status_code == 201
    dup = dict(creds, email=f"{uuid.uuid4().hex[:12]}@e.com")  # same username, new email
    resp = await client.post("/auth/signup", json=dup)
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_signup_empty_password_422(client):
    # #29: an empty (or short) password must be rejected 422, not provisioned 201.
    resp = await client.post("/auth/signup", json=dict(_creds(), password=""))
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_signup_short_password_422(client):
    resp = await client.post("/auth/signup", json=dict(_creds(), password="short"))  # < 8
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_signup_invalid_email_422(client):
    resp = await client.post("/auth/signup", json=dict(_creds(), email="not-an-email"))
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_signup_short_username_422(client):
    resp = await client.post("/auth/signup", json=dict(_creds(), username="ab"))  # < 3
    assert resp.status_code == 422
