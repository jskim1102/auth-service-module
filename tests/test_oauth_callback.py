"""phase6.ckpt1 ← F8 — GET /auth/oauth/{provider}/callback.

Validates (atomically consumes) the state, exchanges the code with the PKCE
verifier (provider HTTP mocked), trusts only an email_verified profile, finds the
user by (provider, provider_uid) else auto-provisions (null username/password) and
links auth_identities, issues tokens, sets the refresh httpOnly cookie, and
redirects to a WHITELISTED host URL carrying a short-lived single-use one-time
code (raw tokens never in the URL).

NEGATIVE: redirect not in ALLOWED_REDIRECT_URIS → 400, no token. email_verified
false → no provision/link → error.
"""
import asyncio
import hashlib
import urllib.parse as up
import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

import app.oauth.providers as providers
from app.db import get_session, make_engine
from app.models import AuthIdentity, OAuthCode, OAuthState, RefreshToken, User
from app.routes.oauth import router
from tests.test_migration import _async_test_url

WHITELISTED = "http://localhost:5176/auth/callback"


def _hash(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


@pytest.fixture(autouse=True)
def _redirect_base(monkeypatch):
    # Pin ALL redirect env the tests assume — never inherit the live .env, which
    # legitimately changes for deployment (e.g. a cloudflare tunnel / public IP).
    # is_allowed_redirect reads ALLOWED_REDIRECT_URIS via lru-cached get_settings,
    # so set it + CORS_ORIGINS to the localhost base AND clear the cache (#23).
    monkeypatch.setenv("OAUTH_REDIRECT_BASE", "http://localhost:5176")
    monkeypatch.setenv("ALLOWED_REDIRECT_URIS", "http://localhost:5176/auth/callback")
    monkeypatch.setenv("CORS_ORIGINS", "http://localhost:5176")
    from app.config import get_settings
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()  # don't leak the pinned Settings to other tests


@pytest_asyncio.fixture
async def factory():
    engine = make_engine(_async_test_url())
    sf = async_sessionmaker(engine, expire_on_commit=False)
    yield sf
    await engine.dispose()


class _FakeResp:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


class _FakeAsyncClient:
    """Stand-in for httpx.AsyncClient that returns canned provider-shaped payloads.

    Mocks ONLY the transport — the real exchange_code / fetch_userinfo (incl. the
    per-provider normalization) run against these REAL-shaped responses, so a
    normalization bug can't hide behind a pre-normalized mock.
    """
    _token = {"access_token": "provider-access-token"}
    # Default: REAL Google OIDC userinfo shape (sub, not provider_uid).
    userinfo = {"sub": "ext-123", "email": "sns@e.com", "email_verified": True}

    def __init__(self, *a, **k):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, url, **kwargs):  # token exchange
        return _FakeResp(self._token)

    async def get(self, url, **kwargs):  # userinfo
        return _FakeResp(_FakeAsyncClient.userinfo)


@pytest.fixture(autouse=True)
def _mock_provider(monkeypatch):
    """Mock the HTTP TRANSPORT (httpx) only — real normalization runs.

    Tests set `_mock_provider["userinfo"]` to a REAL provider payload shape to
    flip email_verified / provider_uid / provider.
    """
    _FakeAsyncClient.userinfo = {"sub": "ext-123", "email": "sns@e.com", "email_verified": True}
    monkeypatch.setattr(providers.httpx, "AsyncClient", _FakeAsyncClient)

    class _State:
        def __setitem__(self, key, value):
            if key == "userinfo":
                _FakeAsyncClient.userinfo = value

    return _State()


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


async def _seed_state(factory, provider="google", *, ttl=600, used=False):
    raw_state = uuid.uuid4().hex + uuid.uuid4().hex
    async with factory() as s:
        s.add(OAuthState(
            state_hash=_hash(raw_state),
            code_verifier="verifier-xyz",
            provider=provider,
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=ttl),
            used=used,
        ))
        await s.commit()
    return raw_state


async def _cb(client, provider, raw_state, *, code="prov-code"):
    # Drive the callback the REAL way providers do: ONLY code + state, no
    # redirect_uri (a required redirect_uri param was the #21 bug — 422 on real
    # provider callbacks).
    return await client.get(
        f"/auth/oauth/{provider}/callback",
        params={"state": raw_state, "code": code},
        follow_redirects=False,
    )


@pytest.mark.asyncio
async def test_callback_auto_provisions_and_redirects_with_one_time_code(client, factory):
    raw_state = await _seed_state(factory, "google")
    resp = await _cb(client, "google", raw_state)
    assert resp.status_code in (302, 303)
    location = resp.headers["location"]
    assert location.startswith(WHITELISTED)
    qs = up.parse_qs(up.urlparse(location).query)
    one_time = qs.get("code", [None])[0]
    assert one_time, "one-time code missing from redirect"
    # Raw tokens must NEVER appear in the redirect URL.
    assert "access_token" not in location and "refresh_token" not in location
    # #28 P1: callback mints ONLY the one-time code — it does NOT set a refresh
    # cookie and does NOT issue a refresh (exchange is the sole token/cookie issuer).
    assert "set-cookie" not in {k.lower() for k in resp.headers}
    # User auto-provisioned with null username/password + linked identity.
    async with factory() as s:
        user = (await s.execute(select(User).where(User.email == "sns@e.com"))).scalar_one()
        ident = (await s.execute(select(AuthIdentity).where(AuthIdentity.user_id == user.id))).scalar_one()
        code_row = (await s.execute(select(OAuthCode).where(OAuthCode.code_hash == _hash(one_time)))).scalar_one()
        refreshes = (await s.execute(select(RefreshToken).where(RefreshToken.user_id == user.id))).scalars().all()
    assert user.username is None and user.password_hash is None
    assert ident.provider == "google" and ident.provider_uid == "ext-123"
    assert code_row.used is False and code_row.user_id == user.id
    assert refreshes == []  # no orphan refresh issued at callback (only exchange issues)


@pytest.mark.asyncio
async def test_callback_consumes_state_once(client, factory):
    raw_state = await _seed_state(factory, "google")
    first = await _cb(client, "google", raw_state)
    assert first.status_code in (302, 303)
    # Replaying the same state must fail (state already consumed).
    second = await _cb(client, "google", raw_state)
    assert second.status_code == 400


@pytest.mark.asyncio
async def test_callback_existing_identity_reused_not_duplicated(client, factory):
    # Pre-existing user + linked identity → callback must reuse, not create a 2nd.
    async with factory() as s:
        u = User(email="sns@e.com")
        s.add(u); await s.flush()
        s.add(AuthIdentity(user_id=u.id, provider="google", provider_uid="ext-123", email="sns@e.com"))
        await s.commit()
    raw_state = await _seed_state(factory, "google")
    resp = await _cb(client, "google", raw_state)
    assert resp.status_code in (302, 303)
    async with factory() as s:
        users = (await s.execute(select(User).where(User.email == "sns@e.com"))).scalars().all()
        idents = (await s.execute(select(AuthIdentity).where(AuthIdentity.provider_uid == "ext-123"))).scalars().all()
    assert len(users) == 1
    assert len(idents) == 1


@pytest.mark.asyncio
async def test_callback_off_whitelist_success_url_400_no_token(client, factory, monkeypatch):
    # The host success URL is configured (OAUTH_REDIRECT_BASE), not client-supplied.
    # A misconfig pointing off the ALLOWED_REDIRECT_URIS whitelist → 400, no side effects.
    monkeypatch.setenv("OAUTH_REDIRECT_BASE", "http://evil.example.com")
    raw_state = await _seed_state(factory, "google")
    resp = await _cb(client, "google", raw_state)
    assert resp.status_code == 400
    # Whitelist-first: no state burned, no user provisioned, no one-time code minted.
    async with factory() as s:
        users = (await s.execute(select(User))).scalars().all()
        codes = (await s.execute(select(OAuthCode))).scalars().all()
    assert users == [] and codes == []


@pytest.mark.asyncio
async def test_callback_unverified_email_id_only_no_email_link(client, factory, _mock_provider):
    # #26: an UNVERIFIED email is not trusted → id-only provisioning. The user is
    # created with email NULL (no email-based linking), identified by (provider,uid).
    _mock_provider["userinfo"] = {"sub": "ext-999", "email": "unv@e.com", "email_verified": False}
    raw_state = await _seed_state(factory, "google")
    resp = await _cb(client, "google", raw_state)
    assert resp.status_code == 302  # id-only success, not 403
    async with factory() as s:
        user = (await s.execute(select(User))).scalar_one()
        ident = (await s.execute(select(AuthIdentity).where(AuthIdentity.provider_uid == "ext-999"))).scalar_one()
    assert user.email is None  # unverified email NOT written to the user record
    assert ident.user_id == user.id and ident.provider == "google"


@pytest.mark.asyncio
async def test_callback_unverified_email_does_not_hijack_existing_account(client, factory, _mock_provider):
    # #26 security: an unverified email matching an existing user must NOT link to it.
    async with factory() as s:
        victim = User(email="unv@e.com", username="victim", password_hash="x")
        s.add(victim); await s.flush(); victim_id = victim.id
        await s.commit()
    _mock_provider["userinfo"] = {"sub": "ext-attacker", "email": "unv@e.com", "email_verified": False}
    raw_state = await _seed_state(factory, "google")
    resp = await _cb(client, "google", raw_state)
    assert resp.status_code == 302
    async with factory() as s:
        ident = (await s.execute(select(AuthIdentity).where(AuthIdentity.provider_uid == "ext-attacker"))).scalar_one()
    assert ident.user_id != victim_id  # linked to a NEW id-only user, not the victim


@pytest.mark.asyncio
async def test_callback_unknown_state_400(client, factory):
    resp = await _cb(client, "google", "never-issued-state")
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_callback_expired_state_400(client, factory):
    raw_state = await _seed_state(factory, "google", ttl=-1)  # already expired
    resp = await _cb(client, "google", raw_state)
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_concurrent_callback_consumes_state_exactly_once(factory, _mock_provider):
    """State single-use under REAL cross-connection concurrency (pooled engine, own
    backend per request). Exactly one callback wins the state → ≤1 redirect, 0×500,
    and only ONE user is auto-provisioned (no duplicate accounts from a state race)."""
    N = 12
    raw_state = await _seed_state(factory, "google")
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
                r = await ac.get(
                    "/auth/oauth/google/callback",
                    params={"state": raw_state, "code": "c", "redirect_uri": WHITELISTED},
                    follow_redirects=False,
                )
                return r.status_code
            codes = await asyncio.gather(*[attempt() for _ in range(N)])
    finally:
        await engine.dispose()

    cnt = Counter(codes)
    assert cnt.get(500, 0) == 0, f"server error under concurrency: {dict(cnt)}"
    assert cnt.get(302, 0) == 1, f"state consumed != once (redirects): {dict(cnt)}"
    # No duplicate user from a state race.
    async with factory() as s:
        users = (await s.execute(select(User).where(User.email == "sns@e.com"))).scalars().all()
    assert len(users) == 1


@pytest.mark.asyncio
async def test_callback_no_email_id_only_provisions_user(client, factory, _mock_provider):
    # #26: a profile with NO email (e.g. Kakao pre-email-review) → id-only user
    # (email NULL), identified by (provider, uid). No 403, no IntegrityError.
    _mock_provider["userinfo"] = {"sub": "ext-noemail", "email": None, "email_verified": True}
    raw_state = await _seed_state(factory, "google")
    resp = await _cb(client, "google", raw_state)
    assert resp.status_code == 302
    async with factory() as s:
        user = (await s.execute(select(User))).scalar_one()
        ident = (await s.execute(select(AuthIdentity).where(AuthIdentity.provider_uid == "ext-noemail"))).scalar_one()
    assert user.email is None and user.username is None and user.password_hash is None
    assert ident.user_id == user.id


@pytest.mark.asyncio
async def test_callback_no_email_returning_user_reused_by_uid(client, factory, _mock_provider):
    # #26: a returning id-only SNS user (no email) is re-identified by (provider,uid),
    # not duplicated.
    _mock_provider["userinfo"] = {"sub": "ext-return", "email": None, "email_verified": True}
    first_state = await _seed_state(factory, "google")
    r1 = await _cb(client, "google", first_state)
    assert r1.status_code == 302
    second_state = await _seed_state(factory, "google")
    r2 = await _cb(client, "google", second_state)
    assert r2.status_code == 302
    async with factory() as s:
        users = (await s.execute(select(User))).scalars().all()
        idents = (await s.execute(select(AuthIdentity).where(AuthIdentity.provider_uid == "ext-return"))).scalars().all()
    assert len(users) == 1 and len(idents) == 1  # reused, not duplicated


@pytest.mark.asyncio
async def test_callback_existing_email_links_new_provider_no_500(client, factory, _mock_provider):
    # A user already owns this email (e.g. local signup). A verified SNS login with
    # the SAME email + a NEW provider_uid must LINK to that user, not 500 on the
    # users.email UNIQUE constraint nor create a duplicate account.
    async with factory() as s:
        u = User(email="sns@e.com", username="local-user", password_hash="x")
        s.add(u); await s.flush()
        existing_id = u.id
        await s.commit()
    _mock_provider["userinfo"] = {"sub": "ext-new", "email": "sns@e.com", "email_verified": True}
    raw_state = await _seed_state(factory, "google")
    resp = await _cb(client, "google", raw_state)
    assert resp.status_code in (302, 303)
    async with factory() as s:
        users = (await s.execute(select(User).where(User.email == "sns@e.com"))).scalars().all()
        ident = (await s.execute(select(AuthIdentity).where(AuthIdentity.provider_uid == "ext-new"))).scalar_one()
    assert len(users) == 1  # no duplicate account
    assert ident.user_id == existing_id  # linked to the pre-existing user


@pytest.mark.asyncio
async def test_callback_naver_error_in_200_is_clean_4xx_not_500(client, factory, _mock_provider):
    # #20: Naver returns auth-fail/cancel as HTTP 200 + {resultcode!="00", no response}.
    # Unguarded response["id"] would KeyError → 500. Must be a clean 4xx.
    _mock_provider["userinfo"] = {"resultcode": "024", "message": "user cancelled"}
    raw_state = await _seed_state(factory, "naver")
    resp = await _cb(client, "naver", raw_state)
    assert 400 <= resp.status_code < 500
    async with factory() as s:
        users = (await s.execute(select(User))).scalars().all()
    assert users == []  # no provision on a provider error


@pytest.mark.asyncio
async def test_callback_email_verified_string_false_is_untrusted_id_only(client, factory, _mock_provider):
    # #20 + #26: bool("false") == True would let the string "false" pass the verified
    # gate. Explicit truthiness treats "false" as UNVERIFIED → the email is NOT trusted,
    # so id-only provisioning (user.email stays NULL, email NOT linked to x@e.com).
    _mock_provider["userinfo"] = {"sub": "ext-strfalse", "email": "x@e.com", "email_verified": "false"}
    raw_state = await _seed_state(factory, "google")
    resp = await _cb(client, "google", raw_state)
    assert resp.status_code == 302  # id-only (unverified email is just not trusted)
    async with factory() as s:
        user = (await s.execute(select(User))).scalar_one()
    assert user.email is None  # the string-"false" email was NOT trusted/written


@pytest.mark.asyncio
async def test_callback_accepts_real_provider_shape_code_state_only(client, factory):
    # #21: the exact real-provider redirect — ONLY code + state, NO redirect_uri.
    # Previously required redirect_uri → 422 on every real callback. Must now 302
    # to the configured success URL with the one-time code.
    raw_state = await _seed_state(factory, "google")
    resp = await client.get(
        "/auth/oauth/google/callback",
        params={"code": "prov-code", "state": raw_state},  # no redirect_uri
        follow_redirects=False,
    )
    assert resp.status_code == 302  # NOT 422
    location = resp.headers["location"]
    assert location.startswith(WHITELISTED)
    assert "code=" in up.urlparse(location).query


@pytest.mark.asyncio
async def test_callback_provider_error_redirect_is_clean_400_not_422(client, factory):
    # #25: provider denial/cancel/invalid_scope redirects back with
    # ?error=&error_description=&state= and NO code. Must be a clean 400 with the
    # provider's message — never 422 (schema error from a required `code`).
    raw_state = await _seed_state(factory, "kakao")
    resp = await client.get(
        "/auth/oauth/kakao/callback",
        params={
            "error": "invalid_scope",
            "error_description": "Invalid scope: account_email",
            "state": raw_state,
        },  # NO code
        follow_redirects=False,
    )
    assert resp.status_code == 400  # NOT 422
    assert "account_email" in resp.json()["detail"]  # surfaces the provider message
    # No user provisioned, no one-time code minted on a provider error.
    async with factory() as s:
        users = (await s.execute(select(User))).scalars().all()
        codes = (await s.execute(select(OAuthCode))).scalars().all()
    assert users == [] and codes == []


@pytest.mark.asyncio
async def test_callback_missing_code_is_clean_400_not_422(client, factory):
    # A bare callback with neither code nor error (malformed) → clean 400, not 422.
    raw_state = await _seed_state(factory, "google")
    resp = await client.get(
        "/auth/oauth/google/callback",
        params={"state": raw_state},  # no code, no error
        follow_redirects=False,
    )
    assert resp.status_code == 400
