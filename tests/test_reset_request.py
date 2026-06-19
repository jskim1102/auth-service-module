"""phase5.ckpt1 #11 — POST /auth/password/reset-request (F7, no enumeration).

Always returns 202 with an IDENTICAL body whether or not the account exists
(account-enumeration defense). On an existing account it stores a single-use,
time-limited, hashed token in password_resets and sends the reset email; on a
non-existing account it stores nothing and sends nothing — but the response is
byte-identical so the caller can't tell the difference.

SMTP is mocked (app.email.send_reset_email) — live MailHog delivery is verified
in the phase8.ckpt3 compose smoke. Same local-app harness as phase4 tests.
"""
import uuid

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.db import get_session, make_engine
from app.models import PasswordReset, User
from app.routes.auth_reset import _mask_email, router
from app.security.hashing import hash_password
from tests.test_migration import _async_test_url


@pytest_asyncio.fixture
async def factory():
    # DB isolation is handled centrally by the autouse _clean_db fixture (conftest).
    engine = make_engine(_async_test_url())
    sf = async_sessionmaker(engine, expire_on_commit=False)
    yield sf
    await engine.dispose()


@pytest.fixture
def sent(monkeypatch):
    """Capture reset-email sends instead of hitting SMTP."""
    calls = []

    async def _fake_send(to_email, token):
        calls.append((to_email, token))

    monkeypatch.setattr("app.routes.auth_reset.send_reset_email", _fake_send)
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
async def test_reset_by_email_sends_and_hints(client, factory, existing_user, sent):
    # Lookup by EMAIL → token stored, email sent, 202 with a masked hint (#31).
    resp = await client.post(
        "/auth/password/reset-request", json={"identifier": existing_user["email"]}
    )
    assert resp.status_code == 202
    assert _mask_email(existing_user["email"]) in resp.json()["message"]
    async with factory() as s:
        user = (await s.execute(select(User).where(User.email == existing_user["email"]))).scalar_one()
        row = (await s.execute(select(PasswordReset).where(PasswordReset.user_id == user.id))).scalar_one()
    assert row.used is False and row.expires_at is not None
    assert len(sent) == 1
    sent_email, raw_token = sent[0]
    assert sent_email == existing_user["email"]
    assert row.token_hash != raw_token  # stored hashed, not plaintext


@pytest.mark.asyncio
async def test_reset_by_username_sends_and_hints(client, factory, existing_user, sent):
    # Lookup by USERNAME (the #31 point — user logs in by id, forgot the email).
    resp = await client.post(
        "/auth/password/reset-request", json={"identifier": existing_user["username"]}
    )
    assert resp.status_code == 202
    assert _mask_email(existing_user["email"]) in resp.json()["message"]
    assert len(sent) == 1 and sent[0][0] == existing_user["email"]


@pytest.mark.asyncio
async def test_mask_email_format():
    # Rule: first char + one '*' per remaining local char, full domain. The local
    # "js.kim.deepi" is 12 chars → 1 + 11 stars (the spec example undercounted stars).
    assert _mask_email("js.kim.deepi@gmail.com") == "j" + "*" * 11 + "@gmail.com"
    assert _mask_email("a@e.com") == "a@e.com"  # 1-char local unchanged
    assert _mask_email("ab@x.io") == "a*@x.io"


@pytest.mark.asyncio
async def test_unknown_identifier_generic_202_no_hint(client, factory, sent):
    # option-a: unknown identifier → generic 202, NO hint, no token, no send.
    resp = await client.post(
        "/auth/password/reset-request", json={"identifier": f"nobody-{uuid.uuid4().hex[:8]}"}
    )
    assert resp.status_code == 202
    assert "@" not in resp.json()["message"]  # no masked email leaked
    async with factory() as s:
        rows = (await s.execute(select(PasswordReset))).scalars().all()
    assert rows == [] and sent == []


@pytest.mark.asyncio
async def test_sns_id_only_account_no_email_generic_202_no_hint(client, factory, sent):
    # option-a: an account with NO email (SNS id-only) → generic 202, no hint, no send.
    username = f"sns-{uuid.uuid4().hex[:8]}"
    async with factory() as s:
        s.add(User(email=None, username=username, password_hash=None))
        await s.commit()
    resp = await client.post("/auth/password/reset-request", json={"identifier": username})
    assert resp.status_code == 202
    assert "@" not in resp.json()["message"]
    async with factory() as s:
        rows = (await s.execute(select(PasswordReset))).scalars().all()
    assert rows == [] and sent == []


# --- #30: app.email.send_reset_email SMTP auth/STARTTLS via env -----------------
@pytest.mark.asyncio
async def test_email_mailhog_default_no_auth_no_tls(monkeypatch):
    # Default (no SMTP_USER/PASSWORD, STARTTLS off) → MailHog path: no auth kwargs,
    # start_tls False. The aiosmtplib.send transport is mocked to capture kwargs.
    import app.email as email_mod

    monkeypatch.setenv("SMTP_HOST", "mailhog")
    monkeypatch.setenv("SMTP_PORT", "1025")
    monkeypatch.setenv("SMTP_FROM", "no-reply@auth.local")
    monkeypatch.setenv("APP_BASE_URL", "http://localhost:5176")
    monkeypatch.delenv("SMTP_USER", raising=False)
    monkeypatch.delenv("SMTP_PASSWORD", raising=False)
    monkeypatch.setenv("SMTP_STARTTLS", "false")

    captured = {}

    async def fake_send(message, **kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(email_mod.aiosmtplib, "send", fake_send)
    await email_mod.send_reset_email("u@e.com", "tok")
    assert captured["hostname"] == "mailhog" and captured["port"] == 1025
    assert captured["start_tls"] is False
    assert "username" not in captured and "password" not in captured


@pytest.mark.asyncio
async def test_email_body_contains_clickable_reset_link(monkeypatch):
    # #32: the email body must carry a clickable {APP_BASE_URL}/reset?token=<t> link
    # (the SPA /reset page prefills the token) — not just the raw token.
    import app.email as email_mod

    monkeypatch.setenv("SMTP_HOST", "mailhog")
    monkeypatch.setenv("SMTP_PORT", "1025")
    monkeypatch.setenv("SMTP_FROM", "no-reply@auth.local")
    monkeypatch.setenv("APP_BASE_URL", "https://app.example.com")
    monkeypatch.delenv("SMTP_USER", raising=False)
    monkeypatch.setenv("SMTP_STARTTLS", "false")

    sent_message = {}

    async def fake_send(message, **kwargs):
        sent_message["body"] = message.get_content()

    monkeypatch.setattr(email_mod.aiosmtplib, "send", fake_send)
    await email_mod.send_reset_email("u@e.com", "TOK123")
    body = sent_message["body"]
    assert "https://app.example.com/reset?token=TOK123" in body
    assert "TOK123" in body  # raw token still present as a fallback


@pytest.mark.asyncio
async def test_email_real_smtp_passes_auth_and_starttls(monkeypatch):
    # Gmail-style: SMTP_USER/PASSWORD set + STARTTLS true → send gets username,
    # password, start_tls=True.
    import app.email as email_mod

    monkeypatch.setenv("SMTP_HOST", "smtp.gmail.com")
    monkeypatch.setenv("SMTP_PORT", "587")
    monkeypatch.setenv("SMTP_FROM", "you@gmail.com")
    monkeypatch.setenv("APP_BASE_URL", "http://localhost:5176")
    monkeypatch.setenv("SMTP_USER", "you@gmail.com")
    monkeypatch.setenv("SMTP_PASSWORD", "app-password")
    monkeypatch.setenv("SMTP_STARTTLS", "true")

    captured = {}

    async def fake_send(message, **kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(email_mod.aiosmtplib, "send", fake_send)
    await email_mod.send_reset_email("u@e.com", "tok")
    assert captured["hostname"] == "smtp.gmail.com" and captured["port"] == 587
    assert captured["start_tls"] is True
    assert captured["username"] == "you@gmail.com" and captured["password"] == "app-password"