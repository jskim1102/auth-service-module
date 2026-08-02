"""POST /auth/username/find (아이디 찾기) — email → emails the account's username.

Enumeration-safe: ALWAYS 202 with an IDENTICAL generic body whether or not an
account with that email exists. When a user with that email AND a username exists,
the username is delivered to that inbox — never echoed in the response. Unknown
emails and SNS id-only accounts (username NULL) send nothing. SMTP is mocked (same
local-app harness as the reset-request suite).
"""
import uuid

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.db import get_session, make_engine
from app.models import User
from app.routes.auth_find import router
from app.security.hashing import hash_password
from tests.test_migration import _async_test_url


@pytest_asyncio.fixture
async def factory():
    # DB isolation handled centrally by the autouse _clean_db fixture (conftest).
    engine = make_engine(_async_test_url())
    sf = async_sessionmaker(engine, expire_on_commit=False)
    yield sf
    await engine.dispose()


@pytest.fixture
def sent(monkeypatch):
    """Capture username-email sends instead of hitting SMTP."""
    calls = []

    async def _fake_send(to_email, username):
        calls.append((to_email, username))

    monkeypatch.setattr("app.routes.auth_find.send_username_email", _fake_send)
    return calls


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
async def existing_user(factory):
    email = f"{uuid.uuid4().hex[:12]}@e.com"
    username = f"u-{uuid.uuid4().hex[:8]}"
    async with factory() as s:
        s.add(User(email=email, username=username, password_hash=hash_password("OldPass1!")))
        await s.commit()
    return {"email": email, "username": username}


@pytest.mark.asyncio
async def test_find_by_email_emails_the_username(client, existing_user, sent):
    resp = await client.post("/auth/username/find", json={"email": existing_user["email"]})
    assert resp.status_code == 202
    # The username is delivered to the inbox, NEVER returned in the response body.
    assert existing_user["username"] not in resp.text
    assert len(sent) == 1
    assert sent[0] == (existing_user["email"], existing_user["username"])


@pytest.mark.asyncio
async def test_unknown_email_identical_body_no_send(client, existing_user, sent):
    # Unknown email → byte-identical generic 202 (no enumeration), nothing sent.
    known = await client.post("/auth/username/find", json={"email": existing_user["email"]})
    unknown = await client.post(
        "/auth/username/find", json={"email": f"nobody-{uuid.uuid4().hex[:8]}@e.com"}
    )
    assert unknown.status_code == 202
    assert unknown.json() == known.json()  # caller can't distinguish exists/not
    assert len(sent) == 1  # only the known-email lookup sent anything


@pytest.mark.asyncio
async def test_email_present_but_no_username_no_send(client, factory, sent):
    # SNS id-only account: has a (verified) email but NO username → nothing to recover.
    email = f"{uuid.uuid4().hex[:12]}@e.com"
    async with factory() as s:
        s.add(User(email=email, username=None, password_hash=None))
        await s.commit()
    resp = await client.post("/auth/username/find", json={"email": email})
    assert resp.status_code == 202
    assert sent == []


@pytest.mark.asyncio
async def test_username_email_body_carries_username(monkeypatch):
    # The recovery email must contain the username and target the requested address.
    import app.email as email_mod

    monkeypatch.setenv("SMTP_HOST", "mailhog")
    monkeypatch.setenv("SMTP_PORT", "1025")
    monkeypatch.setenv("SMTP_FROM", "no-reply@auth.local")
    monkeypatch.delenv("SMTP_USER", raising=False)
    monkeypatch.setenv("SMTP_STARTTLS", "false")

    captured = {}

    async def fake_send(message, **kwargs):
        captured["body"] = message.get_content()
        captured["to"] = message["To"]

    monkeypatch.setattr(email_mod.aiosmtplib, "send", fake_send)
    await email_mod.send_username_email("u@e.com", "myhandle")
    assert "myhandle" in captured["body"]
    assert captured["to"] == "u@e.com"
